const fs = require('fs');
const path = require('path');
const Sequelize = require('sequelize');
const basename = path.basename(__filename);
const db = {};

const sequelize = new Sequelize('travel_app', 'travel_user', 'Root123!', {
  host: 'localhost',
  dialect: 'mysql',
  logging: false
});

fs
  .readdirSync(__dirname)
  .filter(file => {
    return (
      file.indexOf('.') !== 0 &&
      file !== basename &&
      file.slice(-3) === '.js'
    );
  })
  .forEach(file => {
    const modelModule = require(path.join(__dirname, file));
    let model;
    // 检查是否为函数（传统 Sequelize 模型）或类（ES6 类）
    if (typeof modelModule === 'function') {
      model = modelModule(sequelize, Sequelize.DataTypes);
    } else if (modelModule && typeof modelModule === 'object') {
      // 处理可能的 ES6 类或对象导出
      model = sequelize.define(modelModule.name, modelModule.attributes, modelModule.options);
    }
    if (model) {
      db[model.name] = model;
    }
  });

Object.keys(db).forEach(modelName => {
  if (db[modelName].associate) {
    db[modelName].associate(db);
  }
});

db.sequelize = sequelize;
db.Sequelize = Sequelize;

module.exports = db;
