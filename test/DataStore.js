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

    const signature = "0x" + toHexString(ret.r) + toHexString(ret.s) + toHexString([ret.v])

    return signature
};

describe("DataStore contract", function () {
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

        const DataStore = await ethers.getContractFactory("DataStore", {
            libraries: {
                Attributes: lib.address,
            },
        });
        const dataStore = await DataStore.deploy(users.address);
        await dataStore.deployed();

        const wallet = new ethers.Wallet(ownerPrivateKey);
        const pk = wallet.privateKey;

        // User registering
        var params = [
            owner.address,
            ethers.utils.keccak256(ethers.utils.toUtf8Bytes("owner" + "systemID")),
            0,
            [],
            owner.address
        ]

        const payload = users.interface.encodeFunctionData('userNew', [...params, new Uint8Array(65)])
        const signature = getSignedMessage(payload, pk, 0)

        await users.userNew(...params, signature)

        return { users, dataStore, owner, pk };
    }

    it("Should store data index update", async function () {
        const { users, dataStore, owner, pk } = await loadFixture(deployFixture);
        const attrs = [
            [8, ethers.utils.arrayify(0x010203)],       // attribute Content
        ];
        const nonce = await dataStore.nonces(owner.address)
        const payload = dataStore.interface.encodeFunctionData('dataUpdate', [attrs, owner.address, new Uint8Array(65)])
        const signature = getSignedMessage(payload, pk, nonce)

        const tx = await dataStore.dataUpdate(attrs, owner.address, signature)
        const receipt = await tx.wait()
        const events = receipt.events;

        assert.ok(Array.isArray(events));
        assert.equal(events.length, 1);
        assert.equal(events[0].event, 'DataUpdate');
        assert.equal(events[0].args.data, '0x010203');
    })
})
