// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
import { ethers } from "hardhat";

const main = async function() {
  // Hardhat always runs the compile task when running scripts with its command
  // line interface.
  //
  // If this script is run directly using `node` you may want to call compile
  // manually to make sure everything is compiled
  // await hre.run('compile');

  // We get the contract to deploy
  const lib = await ethers.getContractFactory("Attributes");
  const Lib = await lib.deploy();
  await Lib.deployed();
  console.log("Attributes  deployed to:", Lib.address);

  const AccessStore = await ethers.getContractFactory("AccessStore");
  const accessStore = await AccessStore.deploy();
  await accessStore.deployed();
  console.log("AccessStore deployed to:", accessStore.address);

  const Users = await ethers.getContractFactory("Users");
  const users = await Users.deploy(accessStore.address);
  await users.deployed();
  console.log("Users deployed to:", users.address);


  const EhrIndexer = await ethers.getContractFactory("EhrIndexer", {
      libraries: {
        Attributes: Lib.address
      }
  });
  const ehrIndexer = await EhrIndexer.deploy(accessStore.address, users.address);
  await ehrIndexer.deployed();
  console.log("EhrIndexer deployed to:", ehrIndexer.address);

  const DataStore = await ethers.getContractFactory("DataStore");
  const dataStore = await DataStore.deploy(users.address);
  await dataStore.deployed();
  console.log("DataStore deployed to:", dataStore.address);
}

export default main;

