const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const secp256k1 = require('secp256k1');
const assert = require('assert');
const { expect } = require("chai");

const methodHashTypes = {
    dataUpdate: ["string","tuple(uint8, bytes)[]","address","bytes"],
};

const ownerPrivateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

function toHexString(byteArray) {
  return Array.from(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('')
}

const getSignedMessage = async (payload, pk, nonce) => {
    payload = payload.slice(0, payload.length - 97*2);
    const payloadHash = ethers.utils.keccak256(payload);
    nonce++;
    const prefixed = ethers.utils.solidityPack(
        ["string", "bytes32", "uint"],
        ["\x19Ethereum Signed Message:\n32", payloadHash, nonce]
    );
    const prefixedHash = ethers.utils.keccak256(prefixed);

    var sig = secp256k1.ecdsaSign(
        ethers.utils.arrayify(prefixedHash),
        ethers.utils.arrayify(pk)
    );

    var ret = {}
    ret.r = sig.signature.slice(0, 32)
    ret.s = sig.signature.slice(32, 64)
    ret.v = sig.recid + 27

    return "0x" + toHexString(ret.r) + toHexString(ret.s) + toHexString([ret.v])
};

describe("Users contract", function () {
    const systemID = "systemID";
    const patientAddress = "0x95f5e95e5871fd1c85a33c41b32d8a5b13b2d412";
    const patientPrivateKey = "0x15a8ebd8cb4a01dffd96d1b9c1e04a1c4356c2cdba603a12f4d4545a342a4a1e";
    const patientSigner = new ethers.Wallet(patientPrivateKey);
    const doctorAddress = "0x98d477eee45f34054db8a1a5313d9f2781a44b6f";
    const doctorPrivateKey = "0x90319f2d647dc5b5e4aa23fbfcc92f693255024b7c47e90b37b002273f426ece";
    const rolePatient = 0;
    const roleDoctor = 1;

    async function deployFixture() {
        const [owner, addr1, addr2] = await ethers.getSigners();

        const AccessStore = await ethers.getContractFactory("AccessStore");
        const accessStore = await AccessStore.deploy();
        await accessStore.deployed();

        const Lib = await ethers.getContractFactory("Attributes");
        const lib = await Lib.deploy();
        await lib.deployed();

        const Users = await ethers.getContractFactory("Users", {
            libraries: {
                Attributes: lib.address,
            },
        });
        const users = await Users.deploy(accessStore.address);
        await users.deployed();

        const wallet = new ethers.Wallet(ownerPrivateKey);
        const pk = wallet.privateKey;

        return { users, owner, pk };
    }

    async function userRegister(role, userID, systemID, userAddress, usersContract, contractOwner, ownerPrivateKey) {
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))

        const params = [
            userAddress,
            userIDHash,
            role,
            [],
            contractOwner.address
        ]

        const nonce = await usersContract.nonces(contractOwner.address);
        const payload = usersContract.interface.encodeFunctionData('userNew', [...params, new Uint8Array(65)]);
        const signature = getSignedMessage(payload, ownerPrivateKey, nonce);

        const user = await usersContract.userNew(...params, signature);
        return user;
    }

    it("Patient registration", async function () {
        const { users, owner, pk } = await loadFixture(deployFixture);

        const userID = "patient";
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))

        await userRegister(roleDoctor, userID, systemID, patientAddress, users, owner, pk);

        const user = await users.getUser(patientAddress);
        assert.equal(user.IDHash, userIDHash);
    })

    it("Doctor registration", async function () {
        const { users, owner, pk } = await loadFixture(deployFixture);

        const userID = "doctor";
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))

        await userRegister(roleDoctor, userID, systemID, doctorAddress, users, owner, pk);

        const user = await users.getUser(doctorAddress);
        assert.equal(user.IDHash, userIDHash);
    })

    it("Getting doctor by code", async function () {
        const { users, owner, pk } = await loadFixture(deployFixture);

        const userID = "doctor";
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))
        const view = new DataView(ethers.utils.arrayify(userIDHash).buffer.slice(0, 8), 0);
        const doctorCode = view.getBigUint64(0) % 99999999n;

        await userRegister(roleDoctor, userID, systemID, doctorAddress, users, owner, pk);

        const user = await users.getUserByCode(doctorCode);
        assert.equal(user.IDHash, userIDHash);
    })

    it("Creating a user group", async function () {
        const { users, owner, pk } = await loadFixture(deployFixture);

        const userID = "patient";
        await userRegister(roleDoctor, userID, systemID, patientAddress, users, owner, pk);

        const groupID = "groupTest";
        const groupIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(groupID + systemID))

        const params = [
            groupIDHash,
            [
                [1, ethers.utils.toUtf8Bytes("test")]   // Attribute: ID: test
            ],
            patientAddress
        ]

        const nonce = await users.nonces(patientAddress);
        const payload = users.interface.encodeFunctionData('userGroupCreate', [...params, new Uint8Array(65)]);
        const signature = getSignedMessage(payload, patientPrivateKey, nonce);

        await users.userGroupCreate(...params, signature);

        const group = await users.userGroupGetByID(groupIDHash);
        assert.equal(ethers.utils.toUtf8String(group.attrs[0].value), "test");
    })

    it("Adding a user to the group", async function () {
        const { users, owner, pk } = await loadFixture(deployFixture);

        // Patient's registration
        const userID = "patient";
        await userRegister(rolePatient, userID, systemID, patientAddress, users, owner, pk);

        // Group registration
        const groupID = "groupTest";
        const groupIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(groupID + systemID))

        var params = [
            groupIDHash,
            [
                [1, ethers.utils.toUtf8Bytes("test")]   // Attribute: ID: test
            ],
            patientAddress
        ]

        var nonce = await users.nonces(patientAddress);
        var payload = users.interface.encodeFunctionData('userGroupCreate', [...params, new Uint8Array(65)]);
        var signature = getSignedMessage(payload, patientPrivateKey, nonce);
        await users.userGroupCreate(...params, signature);

        // Doctor's registration
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("doctor" + systemID))
        await userRegister(roleDoctor, "doctor", systemID, doctorAddress, users, owner, pk);

        // Adding the doctor to the group
        const userIDEncr = new Uint8Array([255, 255, 255]); // For the example, it doesn't matter here.
        const groupAddParams = {
            groupIDHash: ethers.utils.arrayify(groupIDHash),
            userIDHash: ethers.utils.arrayify(userIDHash),
            level: 3, // read
            userIDEncr: userIDEncr,
            keyEncr: new Uint8Array([255, 255, 255]),
            signer: patientAddress,
            signature: new Uint8Array(65)
        };

        nonce = await users.nonces(patientAddress);
        payload = users.interface.encodeFunctionData('groupAddUser', [groupAddParams]);
        signature = getSignedMessage(payload, patientPrivateKey, nonce);
        groupAddParams.signature = signature;

        await users.groupAddUser(groupAddParams);

        const group = await users.userGroupGetByID(groupIDHash);
        assert.equal(group.members[0].userIDHash, userIDHash);
        assert.equal(group.members[0].userIDEncr, ethers.utils.hexlify(userIDEncr));
    })

    it("Removing a user from a group", async function () {
        const { users, owner, pk } = await loadFixture(deployFixture);

        // Patient's registration
        const userID = "patient";
        await userRegister(rolePatient, userID, systemID, patientAddress, users, owner, pk);

        // Group registration
        const groupID = "groupTest";
        const groupIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(groupID + systemID))

        var params = [
            groupIDHash,
            [
                [1, ethers.utils.toUtf8Bytes("test")]   // Attribute: ID: test
            ],
            patientAddress
        ]

        var nonce = await users.nonces(patientAddress);
        var payload = users.interface.encodeFunctionData('userGroupCreate', [...params, new Uint8Array(65)]);
        var signature = getSignedMessage(payload, patientPrivateKey, nonce);
        await users.userGroupCreate(...params, signature);

        // Doctor's registration
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("doctor" + systemID))
        await userRegister(roleDoctor, "doctor", systemID, doctorAddress, users, owner, pk);

        // Adding the doctor to the group
        const userIDEncr = new Uint8Array([255, 255, 255]); // For the example, it doesn't matter here.
        const groupAddUserParams = {
            groupIDHash: ethers.utils.arrayify(groupIDHash),
            userIDHash: ethers.utils.arrayify(userIDHash),
            level: 3, // read
            userIDEncr: userIDEncr,
            keyEncr: new Uint8Array([255, 255, 255]),
            signer: patientAddress,
            signature: new Uint8Array(65)
        };

        nonce = await users.nonces(patientAddress);
        payload = users.interface.encodeFunctionData('groupAddUser', [groupAddUserParams]);
        signature = getSignedMessage(payload, patientPrivateKey, nonce);
        groupAddUserParams.signature = signature;

        await users.groupAddUser(groupAddUserParams);
        var group = await users.userGroupGetByID(groupIDHash);
        assert.equal(group.members.length, 1);

        // Removing the doctor from the group
        const groupRemoveUserParams = [
            groupIDHash,
            userIDHash,
            patientAddress
        ]

        nonce = await users.nonces(patientAddress);
        payload = users.interface.encodeFunctionData('groupRemoveUser', [...groupRemoveUserParams, new Uint8Array(65)]);
        signature = getSignedMessage(payload, patientPrivateKey, nonce);

        await users.groupRemoveUser(...groupRemoveUserParams, signature);
        group = await users.userGroupGetByID(groupIDHash);
        assert.equal(group.members.length, 0);
    })

    it("Removing a user from a group with no access rights", async function () {
        const { users, owner, pk } = await loadFixture(deployFixture);

        // Patient's registration
        const userID = "patient";
        await userRegister(rolePatient, userID, systemID, patientAddress, users, owner, pk);

        // Group registration
        const groupID = "groupTest";
        const groupIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(groupID + systemID))

        var params = [
            groupIDHash,
            [
                [1, ethers.utils.toUtf8Bytes("test")]   // Attribute: ID: test
            ],
            patientAddress
        ]

        var nonce = await users.nonces(patientAddress);
        var payload = users.interface.encodeFunctionData('userGroupCreate', [...params, new Uint8Array(65)]);
        var signature = getSignedMessage(payload, patientPrivateKey, nonce);
        await users.userGroupCreate(...params, signature);

        // Doctor's registration
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("doctor" + systemID))
        await userRegister(roleDoctor, "doctor", systemID, doctorAddress, users, owner, pk);

        // Adding the doctor to the group
        const userIDEncr = new Uint8Array([255, 255, 255]); // For the example, it doesn't matter here.
        const groupAddUserParams = {
            groupIDHash: ethers.utils.arrayify(groupIDHash),
            userIDHash: ethers.utils.arrayify(userIDHash),
            level: 3, // read
            userIDEncr: userIDEncr,
            keyEncr: new Uint8Array([255, 255, 255]),
            signer: patientAddress,
            signature: new Uint8Array(65)
        };

        nonce = await users.nonces(patientAddress);
        payload = users.interface.encodeFunctionData('groupAddUser', [groupAddUserParams]);
        signature = getSignedMessage(payload, patientPrivateKey, nonce);
        groupAddUserParams.signature = signature;

        await users.groupAddUser(groupAddUserParams);
        var group = await users.userGroupGetByID(groupIDHash);
        assert.equal(group.members.length, 1);

        // Doctor's attempt to remove himself from the group
        const groupRemoveUserParams = [
            groupIDHash,
            userIDHash,
            doctorAddress
        ]

        nonce = await users.nonces(doctorAddress);
        payload = users.interface.encodeFunctionData('groupRemoveUser', [...groupRemoveUserParams, new Uint8Array(65)]);
        signature = getSignedMessage(payload, doctorPrivateKey, nonce);

        await expect(
            users.groupRemoveUser(...groupRemoveUserParams, signature)
        ).to.be.revertedWith("DNY");
    })
})
