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
      references: {
        model: 'users',
        key: 'id'
      }
    },
    post_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'posts',
        key: 'id'
      }
    },
    visited_at: {
      type: DataTypes.DATE,
      allowNull: true,
      defaultValue: DataTypes.NOW
    },
    action: {
      type: DataTypes.ENUM('view', 'like', 'favorite'),
      allowNull: true,
      defaultValue: 'view'
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
      allowNull: true
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: true
    }
  }, {
    tableName: 'user_preferences',
    timestamps: true,
    underscored: true
  });

  UserPreference.associate = (models) => {
    UserPreference.belongsTo(models.User, { foreignKey: 'user_id', as: 'User' });
    UserPreference.belongsTo(models.Post, { foreignKey: 'post_id', as: 'Post' });
  };

  return UserPreference;
};
