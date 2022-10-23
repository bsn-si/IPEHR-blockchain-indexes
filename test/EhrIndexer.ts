import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { Contract } from "ethers";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/dist/src/signer-with-address";

const methodHashTypes: Record<string, any[]> = {
  userAdd: ["string", "address", "bytes32", "uint256", "bytes", "uint"],
  groupCreate: ["string", "bytes32", "bytes", "uint"],
  groupAddUser: ["string", "bytes32", "address", "uint256", "bytes", "uint"],
  groupRemoveUser: ["string", "bytes32", "address", "uint"],
};

const getSignedMessage = async (
  _methodName: string,
  _args: any[],
  signer: SignerWithAddress
) => {
  const payload = ethers.utils.defaultAbiCoder.encode(
    methodHashTypes[_methodName],
    [_methodName, ..._args]
  );

  const payloadHash = ethers.utils.keccak256(payload);

  const signature = await signer.signMessage(
    ethers.utils.arrayify(payloadHash)
  );

  return signature;
};

describe("EhrIndexer", function () {
  async function deployIndexerFixture() {
    const lib = await ethers.getContractFactory("SignChecker");
    const Lib = await lib.deploy();
    await Lib.deployed();

    const Indexer = await ethers.getContractFactory("EhrIndexer", {
      libraries: {
        SignChecker: Lib.address,
      },
    });
    const [owner, otherAddress] = await ethers.getSigners();

    const indexer = await Indexer.deploy();

    await indexer.deployed();

    return { Indexer, indexer, owner, otherAddress };
  }

  async function addEhrDoc(
    contract: Contract,
    address?: SignerWithAddress,
    docType?: number
  ) {
    const ehrId = ethers.utils.formatBytes32String("ehrId");
    const ehrDoc = {
      docType: docType || 1,
      status: 0,
      CID: ethers.utils.hexlify(0x113),
      dealCID: ethers.utils.hexlify(0x101033),
      minerAddress: ethers.utils.hexlify(0x91811),
      docUIDEncrypted: ethers.utils.hexlify(0x101010),
      docBaseUIDHash: ethers.utils.formatBytes32String("docBaseUIDHash"),
      version: ethers.utils.formatBytes32String("version"),
      isLast: true,
      timestamp: 1660086539,
    }
    if (address) {
      await contract.connect(address).addEhrDoc(ehrId, Object.values(ehrDoc));
    } else {
      await contract.addEhrDoc(ehrId, Object.values(ehrDoc));
    }
    return { ehrId, ehrDoc };
  }

  it("Should add address to allowed", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);
    expect(await indexer.allowedChange(otherAddress.address)).to.equal(true);
  });

  it("Should add EhrDoc", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    await addEhrDoc(indexer, otherAddress)

    const doc = await indexer.ehrDocs(
      ethers.utils.formatBytes32String("ehrId"),
      1,
      0
    );

    expect(doc.isLast).to.equal(true);
  });

  it("Should set ehr user", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    await indexer
      .connect(otherAddress)
      .setEhrUser(
        ethers.utils.formatBytes32String("userId"),
        ethers.utils.formatBytes32String("ehrId")
      );

    const user = await indexer.ehrUsers(
      ethers.utils.formatBytes32String("userId")
    );

    expect(user).to.equal(ethers.utils.formatBytes32String("ehrId"));
  });

  it("Should set ehrSubject", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    await indexer
      .connect(otherAddress)
      .setEhrSubject(
        ethers.utils.formatBytes32String("subjectKey"),
        ethers.utils.formatBytes32String("ehrId")
      );

    const subject = await indexer.ehrSubject(
      ethers.utils.formatBytes32String("subjectKey")
    );

    expect(subject).to.equal(ethers.utils.formatBytes32String("ehrId"));
  });

  it("Should set docAccess", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    await indexer
      .connect(otherAddress)
      .setDocAccess(
        ethers.utils.formatBytes32String("docAccess"),
        ethers.utils.hexlify(0x10101)
      );

    const access = await indexer.docAccess(
      ethers.utils.formatBytes32String("docAccess")
    );

    expect(access).to.equal(ethers.utils.hexlify(0x10101));
  });

  it("Should perform multicall", async function () {
    const { indexer, owner, otherAddress } = await loadFixture(
      deployIndexerFixture
    );

    const encodedTransaction = indexer.interface.encodeFunctionData(
      "setAllowed",
      [owner.address, true]
    );

    const encodedTransaction1 = indexer.interface.encodeFunctionData(
      "setAllowed",
      [otherAddress.address, true]
    );

    await indexer.multicall([encodedTransaction, encodedTransaction1]);
  });

  it("Should retrieve last ehr doc by type", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    await addEhrDoc(indexer, otherAddress)

    const doc = await indexer.getLastEhrDocByType(
      ethers.utils.formatBytes32String("ehrId"),
      1
    );

    expect(doc.isLast).to.equal(true);
    expect(doc.docType).to.equal(1);
  });

  it("Should delete doc", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    const { ehrId, ehrDoc } = await addEhrDoc(indexer, otherAddress, 3);

    await indexer
      .connect(otherAddress)
      .deleteDoc(ehrId, ehrDoc.docType, ehrDoc.docBaseUIDHash, ehrDoc.version);

    const doc = await indexer.ehrDocs(ehrId, ehrDoc.docType, 0);

    expect(doc.status).to.equal(1)
  });

  it("Should get ehrDoc by version", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    const { ehrId, ehrDoc } = await addEhrDoc(indexer, otherAddress, 3);

    const doc = await indexer.getDocByVersion(
      ehrId,
      ehrDoc.docType,
      ehrDoc.docBaseUIDHash,
      ehrDoc.version
    );

    expect(doc.docUIDEncrypted).to.equal(ehrDoc.docUIDEncrypted);
  });

  it("Should get ehrDoc by base id", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    const { ehrId, ehrDoc } = await addEhrDoc(indexer, otherAddress, 3);

    const doc = await indexer.getDocLastByBaseID(
      ehrId,
      ehrDoc.docType,
      ehrDoc.docBaseUIDHash
    );

    expect(doc.docUIDEncrypted).to.equal(ehrDoc.docUIDEncrypted);
  });

  it("Should get ehrDoc by timestamp", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    const { ehrId, ehrDoc } = await addEhrDoc(indexer, otherAddress, 3);

    const doc = await indexer.getDocByTime(
      ehrId,
      ehrDoc.docType,
      ehrDoc.timestamp
    );

    expect(doc.docUIDEncrypted).to.equal(ehrDoc.docUIDEncrypted);
  });

  it("Should addUser, create group and add user, remove user from group", async function () {
    const { indexer, otherAddress, owner } = await loadFixture(
      deployIndexerFixture
    );

    await indexer.setAllowed(otherAddress.address, true);

    const USER_ID = ethers.utils.formatBytes32String("userId");
    const GROUP_ID = ethers.utils.formatBytes32String("groupId");

    const methodArguments = {
      userAdd: [
        owner.address,
        USER_ID,
        1,
        ethers.utils.hexlify(0x010101),
        1893272400000,
      ],
      groupCreate: [GROUP_ID, ethers.utils.hexlify(0x010101), 1893272400000],
      groupAddUser: [
        GROUP_ID,
        owner.address,
        1,
        ethers.utils.hexlify(0x010101),
        1893272400000,
      ],
      groupRemoveUser: [GROUP_ID, owner.address, 1893272400000],
    };

    const methodSignatures = {
      userAdd: await getSignedMessage(
        "userAdd",
        methodArguments.userAdd,
        owner
      ),
      groupCreate: await getSignedMessage(
        "groupCreate",
        methodArguments.groupCreate,
        owner
      ),
      groupAddUser: await getSignedMessage(
        "groupAddUser",
        methodArguments.groupAddUser,
        owner
      ),
      groupRemoveUser: await getSignedMessage(
        "groupRemoveUser",
        methodArguments.groupRemoveUser,
        owner
      ),
    };

    await indexer
      .connect(otherAddress)
      .userAdd(
        ...methodArguments.userAdd,
        owner.address,
        methodSignatures.userAdd
      );

    const pwdHash = await indexer.getUserPasswordHash(owner.address);

    expect(pwdHash).to.equal(ethers.utils.hexlify(0x010101));

    await indexer
      .connect(otherAddress)
      .groupCreate(
        ...methodArguments.groupCreate,
        owner.address,
        methodSignatures.groupCreate
      );

    const group = await indexer.userGroups(GROUP_ID);

    expect(group).to.equal(ethers.utils.hexlify(0x010101));

    await indexer
      .connect(otherAddress)
      .groupAddUser(
        ...methodArguments.groupAddUser,
        owner.address,
        methodSignatures.groupAddUser
      );

    const groupAccessPayload = ethers.utils.defaultAbiCoder.encode(
      ["bytes32", "bytes32"],
      [USER_ID, GROUP_ID]
    );

    let groupAccess = await indexer.groupAccess(
      ethers.utils.keccak256(groupAccessPayload)
    );

    expect(groupAccess.keyEncrypted).to.equal(ethers.utils.hexlify(0x010101));

    await indexer
      .connect(otherAddress)
      .groupRemoveUser(
        ...methodArguments.groupRemoveUser,
        owner.address,
        methodSignatures.groupRemoveUser
      );

    groupAccess = await indexer.groupAccess(
      ethers.utils.keccak256(groupAccessPayload)
    );

    expect(groupAccess.keyEncrypted).to.equal("0x");
  });
});
