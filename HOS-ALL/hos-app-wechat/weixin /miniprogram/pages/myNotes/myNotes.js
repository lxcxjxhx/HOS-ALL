// 我的游记页面逻辑
const app = getApp()

Page({
  data: {
    avatar:null,
    userInfo: null,
    notes: [],
    loading: false,
    activeTab: 0, 
    account : '',
    password: '',
    tabs: ['已通过', '审核中', '未通过'],
    itemWidth: 0,
    windowWidth: 0,
    tabIndex: 0,
    sliderLeft: 0,
    sliderOffset: 0,
    sliderOffsets: [],
    passedNotes: [], 
    reviewingNotes: [], 
    rejectedNotes: [],
    defaultAvatar: 'cloud://cloud1-4gdvzpwx2337fba5.636c-cloud1-4gdvzpwx2337fba5-1357899509/avatar/默认头像.png'
  },

  onLoad() {
    var avatar = wx.getStorageSync('avatar')
    this.setData({
      avatar:avatar
    })
    this.checkLogin();
    this.loadAllNotes();
  },

  onShow() {
    
  },
  async loadAllNotes() {
    const account = wx.getStorageSync('account')

    try {
      const db = wx.cloud.database()
      const res = await db.collection('travel_notes')
        .where({
          account: account
        })
        .field({
          title: true,
          content: true,
          image: true,
          Review: true,
          avatar: true,
          createTime: true
        })
        .orderBy('createTime', 'desc')
        .get()
  
      const notes = res.data || []
      console.log('原始数据:', notes)

      const passedNotes = notes.filter(item => item.Review === 1)
      const reviewingNotes = notes.filter(item => item.Review === 0)
      const rejectedNotes = notes.filter(item => item.Review === 2)
  
      this.setData({
        passedNotes,
        reviewingNotes,
        rejectedNotes,
        loading: false
      })
  
    } catch (err) {
      console.error('加载失败:', err)
      this.setData({ loading: false })
      wx.showToast({ 
        title: '加载失败，请检查网络', 
        icon: 'none' 
      })
    }
  },
  test(){
    console.log(this.data.passedNotes)
    console.log(this.data.reviewingNotes)
    console.log(this.data.rejectedNotes)
  },
  toDetail(e){
    wx.navigateTo({
      url: `../noteDetail/noteDetail?id=${e.currentTarget.dataset.id}`,
    })
  },
  async checkLogin() {
    const account = wx.getStorageSync('account')
    const password = wx.getStorageSync('password')
    
    if (!password) {
      wx.redirectTo({ url: '/pages/index/index?redirect=/pages/myNotes/myNotes' })
      return
    }
  
    try {
      const db = wx.cloud.database()
      const res = await db.collection('users')
        .where({ account, password })
        .get()
  
      if (res.data.length === 0) {
        wx.redirectTo({ url: '/pages/index/index' })
        return
      }
  
      this.setData({
        account,
        password,
        userInfo: res.data[0]
      })
    } catch (err) {
      console.error('登录验证失败:', err)
      wx.showToast({ title: '登录验证失败', icon: 'none' })
      wx.redirectTo({ url: '/pages/index/index' })
    }
  },

  async loadNotes() {
    this.setData({ loading: true })
    
    try {
      const { activeTab, userInfo } = this.data
      const statusMap = ['', 'pending', 'approved', 'rejected']
      const status = activeTab > 0 ? statusMap[activeTab] : ''
      
      const res = await wx.cloud.callFunction({
        name: 'getUserNotes',
        data: {
          userId: userInfo._id,
          status
        }
      })
      
      this.setData({
        notes: res.result.data,
        loading: false
      })
    } catch (err) {
      console.error('加载游记失败:', err)
      this.setData({ loading: false })
      wx.showToast({
        title: '加载失败',
        icon: 'none'
      })
    }
  },
  async uploadAvatar() {
    if (!this.data.account) {
      wx.showToast({ title: '请先登录', icon: 'none' })
      return
    }
  
    try {
      // 选择图片
      const mediaRes = await wx.chooseMedia({
        count: 1,
        mediaType: ['image'],
        sizeType: ['compressed']
      })
      
      if (!mediaRes.tempFiles[0]?.tempFilePath) return
  
      // 上传到云存储
      const filePath = mediaRes.tempFiles[0].tempFilePath
      const cloudPath = `avatar/${this.data.account}_${Date.now()}${filePath.match(/\.[^.]+?$/)[0]}`
      const uploadRes = await wx.cloud.uploadFile({
        cloudPath,
        filePath
      })
      wx.setStorageSync('avatar', uploadRes)
      this.setData({
        avatar:uploadRes
      })
      // 更新数据库
      const db = wx.cloud.database()
      await db.collection('users')
        .where({ account: this.data.account })
        .update({
          data: {
            avatar: uploadRes.fileID
          }
        })

      // 更新本地数据
      this.setData({
        'userInfo.avatar': uploadRes.fileID
      })
  
      wx.showToast({ title: '头像更新成功', icon: 'success' })
    } catch (err) {
      console.error('头像上传失败:', err)
      wx.showToast({ title: '更新失败，请重试', icon: 'none' })
    }
  },
  onTabClick(e) {
    const index = e.currentTarget.id;
    this.setData({ tabIndex: index });
  },

  swiperChange(e) {
    this.setData({ tabIndex: e.detail.current });
  },
  switchTab(e) {
    const index = e.currentTarget.dataset.index
    this.setData({
      activeTab: index
    }, () => {
      
    })
  },

  // 格式化时间
  formatTime(dateStr) {
    const date = new Date(dateStr)
    return `${date.getFullYear()}-${date.getMonth() + 1}-${date.getDate()}`
  },

  // 跳转到发布页
  navigateToPublish() {
    wx.navigateTo({
      url: '/pages/publishNote/publishNote'
    })
  },

  // 编辑游记
  editNote(e) {
    const id = e.currentTarget.dataset.id
    wx.navigateTo({
      url: `/pages/publishNote/publishNote?id=${id}`
    })
  },

  // 删除游记
  deleteNote(e) {
    const id = e.currentTarget.dataset.id
    const { notes } = this.data
    
    wx.showModal({
      title: '确认删除',
      content: '确定要删除这篇游记吗？删除后无法恢复',
      success: async (res) => {
        if (res.confirm) {
          try {
            await wx.cloud.callFunction({
              name: 'deleteNote',
              data: { id }
            })
            
            // 从列表中移除
            this.setData({
              notes: notes.filter(note => note._id !== id)
            })
            
            wx.showToast({
              title: '删除成功',
              icon: 'success'
            })
          } catch (err) {
            console.error('删除失败:', err)
            wx.showToast({
              title: '删除失败',
              icon: 'none'
            })
          }
        }
      }
    })
  }
})