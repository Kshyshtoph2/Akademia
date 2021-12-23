const getSnakeCase = require("./getSnakeCase");

module.exports = getSingleCommand = ({ name, displayName, assetType }) => {
  return `module.load_balancer[0].${getSnakeCase(
    assetType
  )}.${displayName} ${name}`;
};
