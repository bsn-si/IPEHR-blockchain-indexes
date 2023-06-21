require("hardhat-deploy")
require("hardhat-deploy-ethers")

const { networkConfig } = require("../helper-hardhat-config")

const util = require("util");
const request = util.promisify(require("request"));

const private_key = network.config.accounts[0]
const wallet = new ethers.Wallet(private_key, ethers.provider)

async function callRpc(method, params) {
  var options = {
    method: "POST",
    //url: "https://api.hyperspace.node.glif.io/rpc/v1",
    url: "https://api.calibration.node.glif.io/rpc/v1",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: method,
      params: params,
      id: 1,
    }),
  };
  const res = await request(options);
  return JSON.parse(res.body).result;
}

module.exports = async ({ deployments }) => {
    console.log("Wallet Ethereum Address:", wallet.address)
    const chainId = network.config.chainId
	const priorityFee = await callRpc("eth_maxPriorityFeePerGas");
    console.log("priorityFee:", priorityFee)
    
	// Attributes
  	console.log("Attributes  deploying...");
  	const lib = await ethers.getContractFactory("Attributes");
 	const Lib = await lib.deploy({
        maxPriorityFeePerGas: priorityFee
    });
  	await Lib.deployed();
  	console.log("Attributes  deployed to:", Lib.address);

	// AccessStore
	const AccessStore = await ethers.getContractFactory("AccessStore");
	const accessStore = await AccessStore.deploy({
        maxPriorityFeePerGas: priorityFee
    });
	await accessStore.deployed();
	console.log("AccessStore deployed to:", accessStore.address);

	// Users
	const Users = await ethers.getContractFactory("Users");
	const users = await Users.deploy(accessStore.address, {
        maxPriorityFeePerGas: priorityFee
    });
	await users.deployed();
	console.log("Users deployed to:", users.address);

	// EhrIndexer
	const EhrIndexer = await ethers.getContractFactory("EhrIndexer", {
	  libraries: {
		Attributes: Lib.address
	  }
	});
	const ehrIndexer = await EhrIndexer.deploy(accessStore.address, users.address, {
        maxPriorityFeePerGas: priorityFee
    });
	await ehrIndexer.deployed();
	console.log("EhrIndexer deployed to:", ehrIndexer.address);

	// DataStore
	const DataStore = await ethers.getContractFactory("DataStore");
	const dataStore = await DataStore.deploy(users.address, {
        maxPriorityFeePerGas: priorityFee
    });
	await dataStore.deployed();
	console.log("DataStore deployed to:", dataStore.address);
}

