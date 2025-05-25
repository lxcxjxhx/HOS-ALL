const db = wx.cloud.database();

Page({
  data: {
    account: '',
    password: '',
    isLogging: false // 防止重复登录
  },

  // 账号输入
  onAccountInput(e) {
    this.setData({
      account: e.detail.value.trim() // 添加trim()去除空格
    });
  },

  // 密码输入
  onPasswordInput(e) {
    this.setData({
      password: e.detail.value.trim() 
    });
  },

  // 登录按钮点击
  onLogin() {
    if (this.data.isLogging) return;
    
    const { account, password } = this.data;
    wx.setStorageSync('account', account)
    wx.setStorageSync('password', password)
    this.getUserAvatarByAccount(account)
    if (!account) {
      wx.showToast({
        title: '请输入用户名',
        icon: 'none'
      });
      return;
    }
    
    if (!password) {
      wx.showToast({
        title: '请输入密码',
        icon: 'none'
      });
      return;
    }
    
    this.setData({ isLogging: true });
    wx.showLoading({
      title: '登录中...',
      mask: true
    });
    
    wx.cloud.callFunction({
      name: 'login',
      data: { account, password },
      success: res => {
        if (res.result.success) {
          const userInfo = res.result.data;
          this.handleLoginSuccess(userInfo);
        } else {
          wx.hideLoading();
          this.setData({ isLogging: false });
          wx.showToast({ 
            title: res.result.message || '登录失败', 
            icon: 'none' 
          });
        }
      },
      fail: err => {
        console.error('云函数调用失败', err);
        wx.hideLoading();
        this.setData({ isLogging: false });
        wx.showToast({
          title: '登录失败，请重试',
          icon: 'none'
        });
      }
    });
  },
  getUserAvatarByAccount: function(account) {
    db.collection('users')
      .where({
        account: account 
      })
      .field({        
        avatar: true,
        _id: false       // 不返回_id字段，可根据需求调整
      })
      .get()
      .then(res => {
        if (res.data.length > 0) {
          const avatarUrl = res.data[0].avatar;
          console.log('获取到的头像URL:', avatarUrl);
          wx.setStorageSync('avatar', avatarUrl)
        } else {
          console.log('未找到对应账号的用户');
        }
      })
      .catch(err => {
        console.error('查询失败:', err);
      });
  },
  // 登录成功处理
  handleLoginSuccess(userInfo) {
    const app = getApp();
    
    // 1. 更新全局数据
    app.globalData.userInfo = userInfo;
    
    // 2. 异步保存到本地存储
    wx.setStorage({
      key: 'userInfo',
      data: userInfo,
      success: () => {
        wx.hideLoading();
        this.setData({ isLogging: false });
        
        // 3. 获取当前页面路由和参数
        const pages = getCurrentPages();
        const currentPage = pages[pages.length - 1];
        const options = currentPage.options || {};
        
        // 4. 确定跳转目标
        let targetUrl = '/pages/travelindex/travelindex';
        if (options.redirect) {
          // 如果有重定向参数，优先使用
          targetUrl = decodeURIComponent(options.redirect);
        }
        
        // 5. 执行跳转
        if (pages.length > 1) {
          // 如果有页面栈，使用navigateBack更自然
          wx.navigateBack();
        } else {
          // 否则使用reLaunch清除所有页面历史
          wx.reLaunch({
            url: targetUrl
          });
        }
        
        wx.showToast({ 
          title: '登录成功',
          icon: 'success',
          duration: 1500
        });
      },
      fail: (err) => {
        console.error('存储用户信息失败:', err);
        wx.hideLoading();
        this.setData({ isLogging: false });
        // 即使存储失败也继续跳转，因为全局数据已更新
        wx.reLaunch({
          url: '/pages/travelindex/travelindex'
        });
      }
    });
  },

  // 跳转到注册页面
  navigateToRegister() {
    wx.navigateTo({
      url: '/pages/register/register',
    });
  },
  navigateToT() {
    wx.setStorageSync('username', this.data.account)
    wx.setStorageSync('password', this.data.password)
    wx.navigateTo({
      url: '/pages/publishNote/publishNote',
    });
  },
});