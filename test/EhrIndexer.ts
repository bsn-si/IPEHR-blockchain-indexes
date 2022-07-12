import { expect } from "chai";
import { ethers } from "hardhat";

describe("EhrIndexer", function () {
  it("Should have role DOCTOR_ADMIN set for contract creator after deployment", async function () {
    const Indexer = await ethers.getContractFactory("EhrIndexer");
    const indexer = await Indexer.deploy();
    await indexer.deployed();

    const [owner] = await ethers.getSigners();

    const role = await indexer.DOCTOR_ADMIN();
    expect(await indexer.hasRole(role, owner.address)).to.equal(true);
  });

  it("Should set EhrUser", async function () {
    const Indexer = await ethers.getContractFactory("EhrIndexer");
    const indexer = await Indexer.deploy();
    await indexer.deployed();

    await indexer.setEhrUser(1, 1);
    expect(await indexer.ehrUsers(1)).to.equal(1);
  });

  it("Should add EhrDoc", async function () {
    const Indexer = await ethers.getContractFactory("EhrIndexer");
    const indexer = await Indexer.deploy();
    await indexer.deployed();

    await indexer.addEhrDoc(11, 11, 11, 11, "0x414141", 31313);
  });
});
