module.exports = (sequelize, DataTypes) => {
  const PostRanking = sequelize.define('PostRanking', {
    post_id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      references: {
        model: 'posts',
        key: 'id'
      }
    },
    score: {
      type: DataTypes.DECIMAL(10, 2),
      allowNull: false,
      defaultValue: 0.00
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: true,
      defaultValue: DataTypes.NOW
    }
  }, {
    tableName: 'post_rankings',
    timestamps: false,
    underscored: true
  });

  PostRanking.associate = (models) => {
    PostRanking.belongsTo(models.Post, { foreignKey: 'post_id', as: 'Post' });
  };

  return PostRanking;
};
