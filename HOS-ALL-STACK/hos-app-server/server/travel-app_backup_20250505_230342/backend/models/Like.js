module.exports = (sequelize, DataTypes) => {
    const Like = sequelize.define('Like', {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      user_id: {
        type: DataTypes.INTEGER,
        allowNull: true
      },
      post_id: {
        type: DataTypes.INTEGER,
        allowNull: true
      },
      created_at: {
        type: DataTypes.DATE,
        allowNull: true,
        defaultValue: DataTypes.NOW
      }
    }, {
      tableName: 'likes',
      timestamps: false,
      underscored: true
    });

    Like.associate = (models) => {
      Like.belongsTo(models.User, { foreignKey: 'user_id', as: 'User', allowNull: true });
      Like.belongsTo(models.Post, { foreignKey: 'post_id', as: 'Post', allowNull: true });
    };

    return Like;
  };
