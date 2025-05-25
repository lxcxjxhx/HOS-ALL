// 云函数入口文件
const cloud = require('wx-server-sdk')
cloud.init()

const db = cloud.database()

// 云函数入口函数
exports.main = async (event, context) => {
  const { account, password } = event
  const DEFAULT_AVATAR = 'cloud://cloud1-4gdvzpwx2337fba5.636c-cloud1-4gdvzpwx2337fba5-1357899509/avatar/默认头像.png'
  
  try {
    // 检查账号是否已存在
    const checkRes = await db.collection('users')
      .where({
        account: account
      })
      .get()
    
    if (checkRes.data.length > 0) {
      return {
        success: false,
        message: '该账号已存在'
      }
    }
    
    // 插入新用户数据
    const addRes = await db.collection('users').add({
      data: {
        account: account,
        password: password,
        avatar: DEFAULT_AVATAR,
        createdAt: db.serverDate()
      }
    })
    
    return {
      success: true,
      userInfo: {
        _id: addRes._id,
        account: account
      }
    }
  } catch (err) {
    console.error('注册失败', err)
    return {
      success: false,
      message: '注册失败，请重试'
    }
  }
}