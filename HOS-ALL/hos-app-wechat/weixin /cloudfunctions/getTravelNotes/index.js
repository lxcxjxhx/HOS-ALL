// cloudfunctions/getTravelNotes/index.js
const cloud = require('wx-server-sdk')
cloud.init()

exports.main = async (event, context) => {
  const { keyword, page = 1, pageSize = 10 } = event
  
  const db = cloud.database()
  const _ = db.command
  
  // 构建查询条件
  let query = {
    status: 'published' // 只查询已发布的游记
  }
  
  // 如果有搜索关键词
  if (keyword) {
    query = _.or([
      { title: db.RegExp({ regexp: keyword, options: 'i' }) },
      { authorName: db.RegExp({ regexp: keyword, options: 'i' }) }
    ])
  }
  
  try {
    // 查询游记总数
    const countResult = await db.collection('travel_notes')
      .where(query)
      .count()
    
    // 查询游记列表
    const listResult = await db.collection('travel_notes')
      .where(query)
      .orderBy('createdAt', 'desc') // 按创建时间倒序
      .skip((page - 1) * pageSize)
      .limit(pageSize)
      .get()
    
    return {
      code: 0,
      data: {
        list: listResult.data,
        total: countResult.total,
        page,
        pageSize
      }
    }
  } catch (err) {
    return {
      code: -1,
      message: err.message
    }
  }
}