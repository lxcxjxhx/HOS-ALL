exports.main = async (event) => {
  try {
    const db = cloud.database();
    const _ = db.command;
    
    // 验证必需参数
    if (!event.account) {
      throw new Error('缺少用户账号参数');
    }

    // 添加完整查询条件
    const { data } = await db.collection('notes')
      .where({
        account: event.account,
        Review: _.exists(true) // 确保包含Review字段
      })
      .field({
        _id: 1,
        title: 1,
        content: 1,
        image: 1,
        Review: 1,
        avatar: 1,
        createTime: 1
      })
      .orderBy('createTime', 'desc')
      .get();

    return { data };

  } catch (err) {
    console.error('云函数错误:', err);
    return { 
      errCode: err.errCode || 500,
      errMsg: err.message || '服务器错误'
    };
  }
};