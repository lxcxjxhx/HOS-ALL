Page({
  data: {
    title: '',
    content: '',
    images: [],
    videoSwitch: false,
    videoUrl: '',
    loading: false
  },

  chooseImage() {
    wx.chooseMedia({
      count: 9 - this.data.images.length,
      mediaType: ['image'],
      success: res => {
        const tempFiles = res.tempFiles.map(item => item.tempFilePath)
        this.setData({
          images: [...this.data.images, ...tempFiles]
        })
      }
    })
  },

  deleteImage(e) {
    const index = e.currentTarget.dataset.index
    const images = this.data.images.filter((_, i) => i !== index)
    this.setData({ images })
  },

  videoSwitchChange(e) {
    this.setData({
      videoSwitch: e.detail.value,
      videoUrl: e.detail.value ? this.data.videoUrl : ''
    })
  },

  chooseVideo() {
    wx.chooseMedia({
      mediaType: ['video'],
      success: res => {
        this.setData({
          videoUrl: res.tempFiles[0].tempFilePath
        })
      }
    })
  },
  async formSubmit(e) {
    const { title, content } = e.detail.value
    
    if (!title || !content) {
      return wx.showToast({ title: '标题和内容不能为空', icon: 'none' })
    }
    
    if (this.data.images.length === 0) {
      return wx.showToast({ title: '请至少上传一张图片', icon: 'none' })
    }

    this.setData({ loading: true })
    
    try {
      const imageUrls = await Promise.all(
        this.data.images.map(filePath => this.uploadFile(filePath, 'image'))
      )

      let videoUrl = ''
      if (this.data.videoSwitch && this.data.videoUrl) {
        videoUrl = await this.uploadFile(this.data.videoUrl, 'video')
      }

      const account = wx.getStorageSync('account')
      const avatar = wx.getStorageSync('avatar')

      const db = wx.cloud.database()
      await db.collection('travel_notes').add({
        data: {
          title,
          content,
          image: imageUrls,
          video: videoUrl,
          account,
          avatar,
          createTime: db.serverDate(),
          Review:0
        }
      })

      wx.showToast({ title: '发布成功' })
      setTimeout(() => wx.navigateBack(), 1500)
    } catch (err) {
      console.error(err)
      wx.showToast({ title: '发布失败', icon: 'none' })
    } finally {
      this.setData({ loading: false })
    }
  },

  uploadFile(filePath, type) {
    return new Promise((resolve, reject) => {
      const cloudPath = `${Date.now()}-${Math.floor(Math.random() * 1000)}.${filePath.match(/\.(\w+)$/)[1]}`
      wx.cloud.uploadFile({
        cloudPath,
        filePath,
        config: { env: getApp().globalData.envId }
      }).then(res => {
        resolve(res.fileID)
      }).catch(reject)
    })
  }
})