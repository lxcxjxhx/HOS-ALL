module.exports = (sequelize, DataTypes) => {
    const Favorite = sequelize.define('Favorite', {
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
      tableName: 'favorites',
      timestamps: false,
      underscored: true
    });

    Favorite.associate = (models) => {
      Favorite.belongsTo(models.User, { foreignKey: 'user_id', as: 'User', allowNull: true });
      Favorite.belongsTo(models.Post, { foreignKey: 'post_id', as: 'Post', allowNull: true });
    };

    return Favorite;
  };
