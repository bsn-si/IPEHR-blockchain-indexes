const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const secp256k1 = require('secp256k1');
const assert = require('assert');
const { expect } = require("chai");
const { v4: uuidv4, parse: uuidParse } = require('uuid');
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

describe("Docs contract", function () {
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

        const Docs = await ethers.getContractFactory("EhrIndexer", {
            libraries: {
                Attributes: lib.address,
            },
        });
        const docs = await Docs.deploy(accessStore.address, users.address);
        await docs.deployed();

        const wallet = new ethers.Wallet(ownerPrivateKey);
        const pk = wallet.privateKey;

        return { docs, users, owner, pk };
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

    async function ehrRegister(docsContract, ehrID, userIDHash, ownerAddress, ownerPrivKey) {
        const params = [
            userIDHash,
            ehrID,
            ownerAddress
        ];
        const nonce = await docsContract.nonces(ownerAddress);
        const payload = docsContract.interface.encodeFunctionData('setEhrUser', [...params, new Uint8Array(65)]);
        const signature = getSignedMessage(payload, ownerPrivKey, nonce);

        await docsContract.setEhrUser(...params, signature);
    }

    it("Setting EHR_ID for user", async function () {
        const { docs, users, owner, pk } = await loadFixture(deployFixture);

        const ehrID = [...uuidParse("3efe3319-e0f7-4b96-bb5d-f9998398abf2"), ...new Uint8Array(16)]
        const userID = "patient";
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))

        await ehrRegister(docs, ehrID, userIDHash, owner.address, pk);

        const ehrID2 = await docs.getEhrUser(userIDHash);
        assert.equal(ehrID2, ethers.utils.hexlify(ehrID));
    })

    it("Setting EHR_SUBJECT for user", async function () {
        const { docs, owner, pk } = await loadFixture(deployFixture);

        const ehrID = [...uuidParse("3efe3319-e0f7-4b96-bb5d-f9998398abf2"), ...new Uint8Array(16)]
        const ehrSubjectKey = [...uuidParse("634f3989-d9af-4053-ad54-c33745500074"), ...new Uint8Array(16)]

        const params = [
            ehrSubjectKey,
            ehrID,
            owner.address
        ];
        const nonce = await docs.nonces(owner.address);
        const payload = docs.interface.encodeFunctionData('setEhrSubject', [...params, new Uint8Array(65)]);
        const signature = getSignedMessage(payload, pk, nonce);

        await docs.setEhrSubject(...params, signature);

        const ehrID2 = await docs.ehrSubject(ehrSubjectKey);
        assert.equal(ehrID2, ethers.utils.hexlify(ehrID));
    })

    it("Adding EHR document", async function () {
        const { docs, users, owner, pk } = await loadFixture(deployFixture);

        // Patient's registration
        const userID = "patient";
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))
        await userRegister(rolePatient, userID, systemID, patientAddress, users, owner, pk);

        const ehrID = [...uuidParse("3efe3319-e0f7-4b96-bb5d-f9998398abf2"), ...new Uint8Array(16)]
        await ehrRegister(docs, ehrID, userIDHash, owner.address, pk);

        const addEhrDocParams = {
            docType: 0, // Type EHR
            id: crypto.randomBytes(32),
            version: new Uint8Array(1, 2, 3),
            timestamp: Math.round(new Date() / 1000), 
            attrs: [],
            signer: patientAddress,
            signature: new Uint8Array(65)
        };

        const nonce = await docs.nonces(patientAddress);
        const payload = docs.interface.encodeFunctionData('addEhrDoc', [addEhrDocParams]);
        addEhrDocParams.signature = getSignedMessage(payload, patientPrivateKey, nonce);

        await docs.addEhrDoc(addEhrDocParams);
    })

    it("Getting EHR documents by type", async function () {
        const { docs, users, owner, pk } = await loadFixture(deployFixture);

        const userID = "patient";
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))
        await userRegister(rolePatient, userID, systemID, patientAddress, users, owner, pk);

        const ehrID = [...uuidParse("3efe3319-e0f7-4b96-bb5d-f9998398abf2"), ...new Uint8Array(16)]
        await ehrRegister(docs, ehrID, userIDHash, owner.address, pk);

        const docType = 2; // Type EHR_STATUS

        const addEhrDocParams = {
            docType: docType, // Type EHR_STATUS
            id: crypto.randomBytes(32),
            version: new Uint8Array([1, 2, 3]),
            timestamp: Math.round(new Date() / 1000), 
            attrs: [],
            signer: patientAddress,
            signature: new Uint8Array(65)
        };

        const nonce = await docs.nonces(patientAddress);
        const payload = docs.interface.encodeFunctionData('addEhrDoc', [addEhrDocParams]);
        addEhrDocParams.signature = getSignedMessage(payload, patientPrivateKey, nonce);

        await docs.addEhrDoc(addEhrDocParams);

        const documents = await docs.getEhrDocs(userIDHash, docType)
        assert.equal(documents[0].id, ethers.utils.hexlify(addEhrDocParams.id));
    })

    it("Getting last EHR document by type", async function () {
        const { docs, users, owner, pk } = await loadFixture(deployFixture);

        const userID = "patient";
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))
        await userRegister(rolePatient, userID, systemID, patientAddress, users, owner, pk);

        const ehrID = [...uuidParse("3efe3319-e0f7-4b96-bb5d-f9998398abf2"), ...new Uint8Array(16)]
        await ehrRegister(docs, ehrID, userIDHash, owner.address, pk);

        const docType = 2; // Type EHR_STATUS

        // Adding document 1
        const addEhrDocParams1 = {
            docType: docType, // Type EHR_STATUS
            id: crypto.randomBytes(32),
            version: new Uint8Array([1, 2, 3]),
            timestamp: Math.round(new Date() / 1000), 
            attrs: [],
            signer: patientAddress,
            signature: new Uint8Array(65)
        };

        var nonce = await docs.nonces(patientAddress);
        var payload = docs.interface.encodeFunctionData('addEhrDoc', [addEhrDocParams1]);
        addEhrDocParams1.signature = getSignedMessage(payload, patientPrivateKey, nonce);

        await docs.addEhrDoc(addEhrDocParams1);

        // Adding document 2
        const addEhrDocParams2 = {
            docType: docType, // Type EHR_STATUS
            id: crypto.randomBytes(32),
            version: new Uint8Array([4, 5, 6]),
            timestamp: Math.round(new Date() / 1000), 
            attrs: [],
            signer: patientAddress,
            signature: new Uint8Array(65)
        };

        nonce = await docs.nonces(patientAddress);
        payload = docs.interface.encodeFunctionData('addEhrDoc', [addEhrDocParams2]);
        addEhrDocParams2.signature = getSignedMessage(payload, patientPrivateKey, nonce);

        await docs.addEhrDoc(addEhrDocParams2);

        const doc = await docs.getLastEhrDocByType(ehrID, docType)
        assert.equal(doc.id, ethers.utils.hexlify(addEhrDocParams2.id));
    })

    it("Getting EHR document by version", async function () {
        const { docs, users, owner, pk } = await loadFixture(deployFixture);

        const userID = "patient";
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))
        await userRegister(rolePatient, userID, systemID, patientAddress, users, owner, pk);

        const ehrID = [...uuidParse("3efe3319-e0f7-4b96-bb5d-f9998398abf2"), ...new Uint8Array(16)]
        await ehrRegister(docs, ehrID, userIDHash, owner.address, pk);

        const docType = 3; // Type COMPOSITION
        const docID = uuidv4();
        const docBaseID = docID + "::" + systemID
        const docBaseIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(docBaseID)); 

        const addEhrDocParams = {
            docType: docType,
            id: crypto.randomBytes(32),
            version: crypto.randomBytes(32),
            timestamp: Math.round(new Date() / 1000), 
            attrs: [
                [4, docBaseIDHash]
            ],
            signer: patientAddress,
            signature: new Uint8Array(65)
        };

        const nonce = await docs.nonces(patientAddress);
        const payload = docs.interface.encodeFunctionData('addEhrDoc', [addEhrDocParams]);
        addEhrDocParams.signature = getSignedMessage(payload, patientPrivateKey, nonce);

        await docs.addEhrDoc(addEhrDocParams);

        const doc = await docs.getDocByVersion(ehrID, docType, docBaseIDHash, addEhrDocParams.version)
        assert.equal(doc.id, ethers.utils.hexlify(addEhrDocParams.id));
        assert.equal(doc.version, ethers.utils.hexlify(addEhrDocParams.version));
    })

    it("Getting EHR document by time", async function () {
        const { docs, owner, pk } = await loadFixture(deployFixture);

    })

    it("Getting last EHR document by baseID", async function () {
        const { docs, users, owner, pk } = await loadFixture(deployFixture);

        const userID = "patient";
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))
        await userRegister(rolePatient, userID, systemID, patientAddress, users, owner, pk);

        const ehrID = [...uuidParse("3efe3319-e0f7-4b96-bb5d-f9998398abf2"), ...new Uint8Array(16)]
        await ehrRegister(docs, ehrID, userIDHash, owner.address, pk);

        const docType = 3; // Type COMPOSITION
        const docID = uuidv4();
        const docBaseID = docID + "::" + systemID
        const docBaseIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(docBaseID)); 

        // Adding document 1
        const addEhrDocParams = {
            docType: docType,
            id: crypto.randomBytes(32),
            version: crypto.randomBytes(32),
            timestamp: Math.round(new Date() / 1000), 
            attrs: [
                [4, docBaseIDHash]
            ],
            signer: patientAddress,
            signature: new Uint8Array(65)
        };

        var nonce = await docs.nonces(patientAddress);
        var payload = docs.interface.encodeFunctionData('addEhrDoc', [addEhrDocParams]);
        addEhrDocParams.signature = getSignedMessage(payload, patientPrivateKey, nonce);

        await docs.addEhrDoc(addEhrDocParams);

        // Adding document 2
        const addEhrDocParams2 = {
            docType: docType,
            id: crypto.randomBytes(32),
            version: crypto.randomBytes(32),
            timestamp: Math.round(new Date() / 1000), 
            attrs: [
                [4, docBaseIDHash]
            ],
            signer: patientAddress,
            signature: new Uint8Array(65)
        };

        nonce = await docs.nonces(patientAddress);
        payload = docs.interface.encodeFunctionData('addEhrDoc', [addEhrDocParams2]);
        addEhrDocParams2.signature = getSignedMessage(payload, patientPrivateKey, nonce);

        await docs.addEhrDoc(addEhrDocParams2);

        const doc = await docs.getDocLastByBaseID(userIDHash, docType, docBaseIDHash)
        assert.equal(doc.id, ethers.utils.hexlify(addEhrDocParams2.id));
    })

    it("Setting EHR document access", async function () {
        const { docs, users, owner, pk } = await loadFixture(deployFixture);

        // Patient's registration
        const patientID = "patient";
        const patientIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(patientID + systemID))
        await userRegister(rolePatient, patientID, systemID, patientAddress, users, owner, pk);

        // Doctor's registration
        const doctorID = "doctor"
        await userRegister(roleDoctor, doctorID, systemID, doctorAddress, users, owner, pk);

        // Ehr registration
        const ehrID = [...uuidParse("3efe3319-e0f7-4b96-bb5d-f9998398abf2"), ...new Uint8Array(16)]
        await ehrRegister(docs, ehrID, patientIDHash, owner.address, pk);

        // Adding EHR document
        const addEhrDocParams = {
            docType: 0, // Type EHR
            id: crypto.randomBytes(32),
            version: new Uint8Array([1, 2, 3]),
            timestamp: Math.round(new Date() / 1000), 
            attrs: [],
            signer: patientAddress,
            signature: new Uint8Array(65)
        };

        var nonce = await docs.nonces(patientAddress);
        var payload = docs.interface.encodeFunctionData('addEhrDoc', [addEhrDocParams]);
        addEhrDocParams.signature = getSignedMessage(payload, patientPrivateKey, nonce);

        await docs.addEhrDoc(addEhrDocParams);

        // Granting access to the document to the doctor
        const idHash = ethers.utils.keccak256(addEhrDocParams.id)
        const setDocAccessParams = [
            idHash,
            {
                idHash: idHash,
                idEncr: new Uint8Array(32),
                keyEncr: new Uint8Array(32),
                level: 3 // Read access
            },
            doctorAddress,
            patientAddress
        ]

        nonce = await docs.nonces(patientAddress);
        payload = docs.interface.encodeFunctionData('setDocAccess', [...setDocAccessParams, new Uint8Array(65)]);
        const signature = getSignedMessage(payload, patientPrivateKey, nonce);
        
        await docs.setDocAccess(...setDocAccessParams, signature);
    })

    it("Deleting EHR document", async function () {
        const { docs, users, owner, pk } = await loadFixture(deployFixture);

        const userID = "patient";
        const userIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userID + systemID))
        await userRegister(rolePatient, userID, systemID, patientAddress, users, owner, pk);

        const ehrID = [...uuidParse("3efe3319-e0f7-4b96-bb5d-f9998398abf2"), ...new Uint8Array(16)]
        await ehrRegister(docs, ehrID, userIDHash, owner.address, pk);

        const docType = 3; // Type COMPOSITION
        const docID = uuidv4();
        const docBaseID = docID + "::" + systemID
        const docBaseIDHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(docBaseID)); 

        const addEhrDocParams = {
            docType: docType,
            id: crypto.randomBytes(32),
            version: crypto.randomBytes(32),
            timestamp: Math.round(new Date() / 1000), 
            attrs: [
                [4, docBaseIDHash]
            ],
            signer: patientAddress,
            signature: new Uint8Array(65)
        };

        var nonce = await docs.nonces(patientAddress);
        var payload = docs.interface.encodeFunctionData('addEhrDoc', [addEhrDocParams]);
        addEhrDocParams.signature = getSignedMessage(payload, patientPrivateKey, nonce);

        await docs.addEhrDoc(addEhrDocParams);
        const deleteDocParams = [
            ehrID, 
            docType,
            docBaseIDHash,
            addEhrDocParams.version,
            patientAddress
        ];

        nonce = await docs.nonces(patientAddress);
        payload = docs.interface.encodeFunctionData('deleteDoc', [...deleteDocParams, new Uint8Array(65)]);
        const signature = getSignedMessage(payload, patientPrivateKey, nonce);

        await docs.deleteDoc(...deleteDocParams, signature);

        const doc = await docs.getDocByVersion(ehrID, docType, docBaseIDHash, addEhrDocParams.version);
        assert.equal(doc.status, 1); // 1 = status deleted
    })


})
