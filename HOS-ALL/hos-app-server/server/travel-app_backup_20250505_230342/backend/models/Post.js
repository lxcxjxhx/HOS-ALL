module.exports = (sequelize, DataTypes) => {
  const Post = sequelize.define('Post', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    title: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    content: {
      type: DataTypes.TEXT,
      allowNull: true
    },
    image: {
      type: DataTypes.STRING(512),
      allowNull: true
    },
    status: {
      type: DataTypes.ENUM('pending', 'approved', 'rejected'),
      allowNull: true,
      defaultValue: 'pending'
    },
    reason: {
      type: DataTypes.TEXT,
      allowNull: true
    },
    user_id: {
      type: DataTypes.INTEGER,
      allowNull: true
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
    tableName: 'posts',
    timestamps: true,
    underscored: true
  });

  Post.associate = (models) => {
    Post.belongsTo(models.User, { foreignKey: 'user_id', as: 'User', allowNull: true });
    if (models.Favorite) {
      Post.hasMany(models.Favorite, { foreignKey: 'post_id', as: 'Favorites' });
    }
    if (models.Like) {
      Post.hasMany(models.Like, { foreignKey: 'post_id', as: 'Likes' });
    }
    if (models.PostRanking) {
      Post.hasOne(models.PostRanking, { foreignKey: 'post_id', as: 'Ranking' });
    }
  };

  return Post;
};
