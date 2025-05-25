Page({

  /**
   * 页面的初始数据
   */
  data: {
    noteDetail:{}
  },

  /**
   * 生命周期函数--监听页面加载
   */
  onLoad(options) {
    const noteId = options.id;
    const db = wx.cloud.database();
    db.collection('travel_notes').doc(noteId).get()
      .then(res => {
        const noteData = res.data;
        const mediaList = [];
  
        if (noteData.video) {
          mediaList.push({ type: 'video', url: noteData.video });
        }

        if (noteData.image && noteData.image.length) {
          noteData.image.forEach(url => mediaList.push({ type: 'image', url }));
        }
        this.setData({ 
          noteDetail: noteData,
          mediaList: mediaList
        });
      })
      .catch(console.error);
  },
  /**
   * 生命周期函数--监听页面初次渲染完成
   */
  onReady: function () {
    
  },
  delete(){
    console.log(this.data.noteDetail._id)
    const db = wx.cloud.database();

    wx.showModal({
      title: '确认删除',
      content: '确定要删除这条旅行笔记吗？',
      success: (res) => {
        if (res.confirm) {
          db.collection('travel_notes').doc(this.data.noteDetail._id).remove()
            .then(() => {
              wx.showToast({
                title: '删除成功',
                icon: 'success',
                duration: 2000
              });
  
              // 可选：延迟跳转或刷新页面
              setTimeout(() => {
                wx.navigateBack(); // 返回上一页
              }, 2000);
            })
            .catch(err => {
              console.error('删除失败', err);
              wx.showToast({
                title: '删除失败',
                icon: 'none'
              });
            });
        }
      }
    });
  },
  /**
   * 生命周期函数--监听页面显示
   */
  onShow: function () {
    
  },

  /**
   * 生命周期函数--监听页面隐藏
   */
  onHide: function () {
    
  },

  /**
   * 生命周期函数--监听页面卸载
   */
  onUnload: function () {
    
  },

  /**
   * 页面相关事件处理函数--监听用户下拉动作
   */
  onPullDownRefresh: function () {
    
  },

  /**
   * 页面上拉触底事件的处理函数
   */
  onReachBottom: function () {
    
  },

  /**
   * 用户点击右上角分享
   */
  onShareAppMessage: function () {
    
  }
})