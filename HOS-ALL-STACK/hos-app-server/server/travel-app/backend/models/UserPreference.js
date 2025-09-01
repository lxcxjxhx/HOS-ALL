module.exports = (sequelize, DataTypes) => {
  const UserPreference = sequelize.define('UserPreference', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    user_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      unique: true
    },
    theme: {
      type: DataTypes.ENUM('light', 'dark'),
      allowNull: false,
      defaultValue: 'light'
    },
    notifications_enabled: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: true
    },
    language: {
      type: DataTypes.STRING(10),
      allowNull: false,
      defaultValue: 'zh-CN'
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: true,
      defaultValue: DataTypes.NOW
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: true,
      defaultValue: DataTypes.NOW
    }
  }, {
    tableName: 'user_preferences',
    timestamps: true,
    underscored: true
  });

  UserPreference.associate = (models) => {
    UserPreference.belongsTo(models.User, { foreignKey: 'user_id', as: 'User' });
  };

  return UserPreference;
};
