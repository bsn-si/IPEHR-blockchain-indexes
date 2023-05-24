const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const secp256k1 = require('secp256k1');
const assert = require('assert');
const { expect } = require("chai");
const crypto = require('crypto');

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

describe("AccessStore contract", function () {
    const systemID = "systemID";
    const userAddress = "0x95f5e95e5871fd1c85a33c41b32d8a5b13b2d412";
    const userPrivateKey = "0x15a8ebd8cb4a01dffd96d1b9c1e04a1c4356c2cdba603a12f4d4545a342a4a1e";
    const userSigner = new ethers.Wallet(userPrivateKey);
    const Role = { Patient: 0, Doctor: 1 };
    const AccessKind = { Doc: [...new Uint8Array(31), 1], DocGroup: [...new Uint8Array(31), 2], UserGroup: [...new Uint8Array(31), 3] };
    const AccessLevel = { Owner: [...new Uint8Array(31), 1], Admin: [...new Uint8Array(31), 2], Read: [...new Uint8Array(31), 3] };

    async function deployFixture() {
        const [owner, addr1, addr2] = await ethers.getSigners();

        const AccessStore = await ethers.getContractFactory("AccessStore");
        const accessStore = await AccessStore.deploy();
        await accessStore.deployed();

        const Users = await ethers.getContractFactory("Users");
        const users = await Users.deploy(accessStore.address);
        await users.deployed();

        const wallet = new ethers.Wallet(ownerPrivateKey);
        const pk = wallet.privateKey;

        return { users, accessStore, owner, pk };
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

    it("Setting access rights", async function () {
        const { users, accessStore, owner, pk } = await loadFixture(deployFixture);

        // Users's registration
        const userID = "testUser";
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))
        await userRegister(Role.Patient, userID, systemID, userAddress, users, owner, pk);

        // Setting access to document to the user
        const userAccessID = ethers.utils.keccak256([...ethers.utils.arrayify(userIDHash), ...AccessKind.Doc]);
        const docID = crypto.randomBytes(32);
        const docIDHash = ethers.utils.keccak256(docID);
        const setAccessParams = [
            userAccessID,
            {
                kind: AccessKind.Doc,
                idHash: docIDHash,
                idEncr: new Uint8Array(32),
                keyEncr: new Uint8Array(32),
                level: AccessLevel.Owner
            },
            userAddress
        ];

        nonce = await accessStore.nonces(userAddress);
        payload = accessStore.interface.encodeFunctionData('setAccess', [...setAccessParams, new Uint8Array(65)]);
        var signature = getSignedMessage(payload, userPrivateKey, nonce);
        
        await accessStore.setAccess(...setAccessParams, signature);
    })

    it("Getting access rights by accessID", async function () {
        const { users, accessStore, owner, pk } = await loadFixture(deployFixture);

        // Users's registration
        const userID = "testUser";
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))
        await userRegister(Role.Patient, userID, systemID, userAddress, users, owner, pk);

        // Setting access to document to the user
        const userAccessID = ethers.utils.keccak256([...ethers.utils.arrayify(userIDHash), ...AccessKind.Doc]);
        const docID = crypto.randomBytes(32);
        const docIDHash = ethers.utils.keccak256(docID);
        const setAccessParams = [
            userAccessID,
            {
                kind: AccessKind.Doc,
                idHash: docIDHash,
                idEncr: new Uint8Array(32),
                keyEncr: new Uint8Array(32),
                level: AccessLevel.Owner
            },
            userAddress
        ];

        nonce = await accessStore.nonces(userAddress);
        payload = accessStore.interface.encodeFunctionData('setAccess', [...setAccessParams, new Uint8Array(65)]);
        var signature = getSignedMessage(payload, userPrivateKey, nonce);
        
        await accessStore.setAccess(...setAccessParams, signature);

        const access = await accessStore.getAccessByIdHash(userAccessID, docIDHash);
        assert.equal(access.idHash, docIDHash);
    })

    it("Getting access rights by userID", async function () {
        const { users, accessStore, owner, pk } = await loadFixture(deployFixture);

        // Users's registration
        const userID = "testUser";
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))
        await userRegister(Role.Patient, userID, systemID, userAddress, users, owner, pk);

        // Setting access to document to the user
        const userAccessID = ethers.utils.keccak256([...ethers.utils.arrayify(userIDHash), ...AccessKind.Doc]);
        const docID = crypto.randomBytes(32);
        const docIDHash = ethers.utils.keccak256(docID);
        const setAccessParams = [
            userAccessID,
            {
                kind: AccessKind.Doc,
                idHash: docIDHash,
                idEncr: new Uint8Array(32),
                keyEncr: new Uint8Array(32),
                level: AccessLevel.Owner
            },
            userAddress
        ];

        nonce = await accessStore.nonces(userAddress);
        payload = accessStore.interface.encodeFunctionData('setAccess', [...setAccessParams, new Uint8Array(65)]);
        var signature = getSignedMessage(payload, userPrivateKey, nonce);
        
        await accessStore.setAccess(...setAccessParams, signature);

        const access = await accessStore.userAccess(userIDHash, AccessKind.Doc, docIDHash);
        assert.equal(access.idHash, docIDHash);
    })
})
