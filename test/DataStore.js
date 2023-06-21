const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const secp256k1 = require('secp256k1');
const assert = require('assert');

const methodHashTypes = {
    dataUpdate: ["string","tuple(uint8, bytes)[]","address","bytes"],
};

const ownerPrivateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

function toHexString(byteArray) {
  return Array.from(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('')
}

const getSignedMessage = async (payload, pk, deadline) => {
    payload = payload.slice(0, payload.length - 97*2);
    const payloadHash = ethers.utils.keccak256(payload);
    const prefixed = ethers.utils.solidityPack(
        ["string", "bytes32", "uint"],
        ["\x19Ethereum Signed Message:\n32", payloadHash, deadline]
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

describe("DataStore contract", function () {
    const timeout = 5 * 60; // 5min

    async function deployFixture() {
        const [owner, addr1, addr2] = await ethers.getSigners();

        const AccessStore = await ethers.getContractFactory("AccessStore");
        const accessStore = await AccessStore.deploy();
        await accessStore.deployed();

        const Lib = await ethers.getContractFactory("Attributes");
        const lib = await Lib.deploy();
        await lib.deployed();

        const Users = await ethers.getContractFactory("Users", {
            //libraries: {
            //    Attributes: lib.address,
            //},
        });
        const users = await Users.deploy(accessStore.address);
        await users.deployed();

        const DataStore = await ethers.getContractFactory("DataStore");
        const dataStore = await DataStore.deploy(users.address);
        await dataStore.deployed();

        const wallet = new ethers.Wallet(ownerPrivateKey);
        const pk = wallet.privateKey;
        const deadline = Math.floor(Date.now() / 1000) + timeout;

        // User registering
        var params = [
            owner.address,
            ethers.utils.keccak256(ethers.utils.toUtf8Bytes("owner" + "systemID")),
            0,
            [],
            owner.address,
            deadline
        ]

        const payload = users.interface.encodeFunctionData('userNew', [...params, new Uint8Array(65)])
        const signature = getSignedMessage(payload, pk, deadline)

        await users.userNew(...params, signature)

        return { users, dataStore, owner, pk };
    }

    it("Should store data index update", async function () {
        const { users, dataStore, owner, pk } = await loadFixture(deployFixture);
		const groupID = "0xde1b5b5f7d2e0d0b9481e3fb25d9db0bf76606503411472a684ae43d52488d35"
		const dataID  = "0x41183c352e2a4747d6f301689aee900a64a0b5ff5e2c472b16ebcef67d864d8b"
		const ehrID   = "0xff4f429557f6c8c19d41c8155e4cdd25defaae609ae6d8fb16aaf87fedd5f58c"
		const data    = "0x010203"
        const deadline = Math.floor(Date.now() / 1000) + timeout;
        const payload = dataStore.interface.encodeFunctionData('dataUpdate', [groupID, dataID, ehrID, data, owner.address, deadline, new Uint8Array(65)])
        const signature = getSignedMessage(payload, pk, deadline)

        const tx = await dataStore.dataUpdate(groupID, dataID, ehrID, data, owner.address, deadline, signature)
        const receipt = await tx.wait()
        const events = receipt.events;

        assert.ok(Array.isArray(events));
        assert.equal(events.length, 1);
        assert.equal(events[0].event, 'DataUpdate');
        assert.equal(events[0].args.data, '0x010203');
    })
})
