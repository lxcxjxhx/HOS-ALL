// 删除游记
const cloud = require('wx-server-sdk')
cloud.init()

exports.main = async (event, context) => {
  const { id } = event
  const db = cloud.database()
  
  try {
    // 先获取游记信息校验权限
    const note = await db.collection('travel_notes').doc(id).get()
    if (!note.data) {
      return { code: -1, message: '游记不存在' }
    }
    
    // 校验是否是作者本人操作
    const wxContext = cloud.getWXContext()
    if (note.data.authorId !== wxContext.OPENID) {
      return { code: -1, message: '无权限操作' }
    }
    
    // 执行删除
    await db.collection('travel_notes').doc(id).remove()
    
    return { code: 0 }
  } catch (err) {
    return {
      code: -1,
      message: err.message
    }
  }
}