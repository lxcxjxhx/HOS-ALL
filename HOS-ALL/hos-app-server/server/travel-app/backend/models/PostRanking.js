module.exports = (sequelize, DataTypes) => {
  const PostRanking = sequelize.define('PostRanking', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    post_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      unique: true
    },
    score: {
      type: DataTypes.FLOAT,
      allowNull: false,
      defaultValue: 0
    },
    rank: {
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
    tableName: 'post_rankings',
    timestamps: true,
    underscored: true
  });

  PostRanking.associate = (models) => {
    PostRanking.belongsTo(models.Post, { foreignKey: 'post_id', as: 'Post' });
  };

  return PostRanking;
};
