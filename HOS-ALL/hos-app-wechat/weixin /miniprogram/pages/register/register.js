Page({
  data: {
    account: '',
    password: '',
    confirmPassword: ''
  },

  // 账号输入
  onAccountInput(e) {
    this.setData({
      account: e.detail.value
    });
  },

  // 密码输入
  onPasswordInput(e) {
    this.setData({
      password: e.detail.value
    });
  },

  // 确认密码输入
  onConfirmPasswordInput(e) {
    this.setData({
      confirmPassword: e.detail.value
    });
  },

  // 注册按钮点击
  onRegister() {
    const { account, password, confirmPassword } = this.data;
    
    if (!account) {
      wx.showToast({
        title: '请输入账号',
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
    
    if (password !== confirmPassword) {
      wx.showToast({
        title: '两次密码输入不一致',
        icon: 'none'
      });
      return;
    }
    
    // 调用云函数注册
    wx.showLoading({
      title: '注册中...',
    });
    
    wx.cloud.callFunction({
      name: 'register',
      data: {
        account: account,
        password: password
      },
      success: res => {
        wx.hideLoading();
        if (res.result.success) {
          wx.showToast({
            title: '注册成功',
          });
          // 注册成功后跳转到登录页面
          wx.navigateBack();
        } else {
          wx.showToast({
            title: res.result.message || '注册失败',
            icon: 'none'
          });
        }
      },
      fail: err => {
        wx.hideLoading();
        wx.showToast({
          title: '注册失败，请重试',
          icon: 'none'
        });
        console.error('云函数调用失败', err);
      }
    });
  },

  // 跳转到登录页面
  navigateToLogin() {
    wx.navigateBack();
  }
});