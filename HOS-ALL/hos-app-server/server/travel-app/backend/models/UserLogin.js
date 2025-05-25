module.exports = (sequelize, DataTypes) => {
  const UserLogin = sequelize.define('UserLogin', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    user_id: {
      type: DataTypes.INTEGER,
      allowNull: false
    },
    login_time: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW
    },
    ip_address: {
      type: DataTypes.STRING(45),
      allowNull: true
    }
  }, {
    tableName: 'user_logins',
    timestamps: false,
    underscored: true
  });

  UserLogin.associate = (models) => {
    UserLogin.belongsTo(models.User, { foreignKey: 'user_id', as: 'User' });
  };

  return UserLogin;
};
