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
    },
    device_info: {
      type: DataTypes.TEXT,
      allowNull: true
    },
    session_id: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    expires_at: {
      type: DataTypes.DATE,
      allowNull: false
    },
    jwt_secret: {
      type: DataTypes.STRING(255),
      allowNull: false
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
