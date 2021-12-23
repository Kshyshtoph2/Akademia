const fs = require("fs");
const getSingleCommand = require("./getSingleCommand");

const file = fs.readFileSync("./resources.json");

const arr = JSON.parse(file);

const output1 = arr
  .filter(
    ({ assetType, location }) =>
      assetType != "compute.googleapis.com/Subnetwork" ||
      location == "europe-central"
  )
  .map(({ name, displayName, assetType }) => ({
    name: name.slice(2),
    displayName,
    assetType: assetType.split("/")[1],
  }));

fs.writeFileSync("filtered.json", JSON.stringify(output1, null, 2), {
  encoding: "utf-8",
});

const importCommand =
  "terraform import " +
  output1.map(getSingleCommand).join("\n && terraform import ");
console.log(importCommand);
fs.writeFileSync("./import.sh", importCommand, { encoding: "utf-8" });
