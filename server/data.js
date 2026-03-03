const fs = require("fs");
const path = require("path");

const DATA_FILE = path.join(__dirname, "../db.json");

const defaultData = {
  adminPassword: "admin123",
  groups: [],
};

function loadData() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      saveData(defaultData);
      return defaultData;
    }
    const data = fs.readFileSync(DATA_FILE, "utf8");
    return JSON.parse(data);
  } catch (error) {
    console.error("加载数据失败:", error);
    return defaultData;
  }
}

function saveData(data) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
    return true;
  } catch (error) {
    console.error("保存数据失败:", error);
    return false;
  }
}

module.exports = { loadData, saveData, DATA_FILE };
