// 云函数 login
const cloud = require('wx-server-sdk')
cloud.init()

exports.main = async (event, context) => {
  const { account, password } = event
  const db = cloud.database()
  
  try {
    const { data } = await db.collection('users')
      .where({
        account,
        password
      })
      .field({ // 明确指定返回字段
        _id: true,
        account: true,
        avatar: true,
        nickname: true
      })
      .get()

    if (data.length > 0) {
      return {
        success: true,
        data: data[0],
        message: '登录成功'
      }
    } else {
      return {
        success: false,
        message: '账号或密码错误'
      }
    }
  } catch (err) {
    return {
      success: false,
      message: '服务器错误'
    }
  }
}