import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

describe("EhrIndexer", function () {
  async function deployIndexerFixture() {
    const Indexer = await ethers.getContractFactory("EhrIndexer");
    const [owner, otherAddress] = await ethers.getSigners();

    const indexer = await Indexer.deploy();

    await indexer.deployed();

    return { Indexer, indexer, owner, otherAddress };
  }

  it("Should add address to allowed", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);
    expect(await indexer.allowedChange(otherAddress.address)).to.equal(true);
  });

  it("Should add EhrDoc", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    await indexer
      .connect(otherAddress)
      .addEhrDoc(11, [11, 11, 11, "0x414141", 31313]);

    const doc = await indexer.ehrDocs(11, 0);

    expect(doc[4]).to.equal(31313);
  });

  it("Should set ehr user", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    await indexer.connect(otherAddress).setEhrUser(11, 11);

    const user = await indexer.ehrUsers(11);

    expect(user).to.equal(11);
  });

  it("Should set ehrSubject", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    await indexer.connect(otherAddress).setEhrSubject(11, 11);

    const subject = await indexer.ehrSubject(11);

    expect(subject).to.equal(11);
  });

  it("Should set docAccess", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    await indexer.connect(otherAddress).setDocAccess(11, 0x01);

    const access = await indexer.docAccess(11);

    expect(access).to.equal("0x01");
  });

  it("Should set dataAccess", async function () {
    const { indexer, otherAddress } = await loadFixture(deployIndexerFixture);

    await indexer.setAllowed(otherAddress.address, true);

    await indexer.connect(otherAddress).setDataAccess(11, 0x01);

    const access = await indexer.dataAccess(11);

    expect(access).to.equal("0x01");
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
});
