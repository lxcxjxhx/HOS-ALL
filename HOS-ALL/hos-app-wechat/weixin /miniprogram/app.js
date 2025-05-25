// app.js
App({
  onLaunch: function () {
    if (!wx.cloud) {
      console.error("请使用 2.2.3 或以上的基础库以使用云能力");
    } else {
      wx.cloud.init({
        // env 参数说明：
        //   env 参数决定接下来小程序发起的云开发调用（wx.cloud.xxx）会默认请求到哪个云环境的资源
        //   此处请填入环境 ID, 环境 ID 可打开云控制台查看
        //   如不填则使用默认环境（第一个创建的环境）
        env: "",
        traceUser: true,
      });
    }

    this.globalData = {
      userInfo: null, // 存储登录用户信息
      isLoggedIn: false // 登录状态标识
    };

    // 冷启动时尝试从本地存储恢复登录状态
    this.restoreLoginStatus();
  },

  // 从本地存储恢复登录状态
  restoreLoginStatus: function() {
    try {
      const userInfo = wx.getStorageSync('userInfo');
      if (userInfo) {
        this.globalData.userInfo = userInfo;
        this.globalData.isLoggedIn = true;
      }
    } catch (e) {
      console.error('读取本地存储失败:', e);
    }
  },

  // 更新用户信息（供其他页面调用）
  updateUserInfo: function(userInfo) {
    this.globalData.userInfo = userInfo;
    this.globalData.isLoggedIn = !!userInfo;
    
    // 持久化到本地存储
    wx.setStorage({
      key: 'userInfo',
      data: userInfo
    });
  },
});
