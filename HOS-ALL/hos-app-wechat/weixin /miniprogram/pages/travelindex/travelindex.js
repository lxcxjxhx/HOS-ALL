Page({
  data: {
    columns: [[], []], 
    page: 1,       
    pageSize: 10,  
    loading: false,   
    noMore: false,
    searchKeyword: '',
    userAvatar: 'cloud://cloud1-4gdvzpwx2337fba5.636c-cloud1-4gdvzpwx2337fba5-1357899509/avatar/默认头像.png',
  },

  onLoad() {
    
  },
  onSearchInput(e) {
    const keyword = e.detail.value.trim();
    const escapedKeyword = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    this.setData({
      searchKeyword: escapedKeyword
    });
  },
  executeSearch() {
    // 重置分页数据和状态
    this.setData({
      page: 1,
      columns: [[], []],
      noMore: false
    }, () => {
      this.loadPosts(); // 重新加载数据
    });
  },
  onShow(){

    this.loadPosts();
    const account = wx.getStorageSync("account");
    if (account) {
      const db = wx.cloud.database();
      db.collection('users')
        .where({
          account: account
        })
        .field({
          avatar: true
        })
        .get()
        .then(res => {
          if (res.data.length > 0 && res.data[0].avatar) {
            this.setData({
              userAvatar: res.data[0].avatar
            });
          }
        })
        .catch(err => {
          console.error('用户头像查询失败:', err);
          wx.showToast({ 
            title: '头像加载失败', 
            icon: 'none' 
          });
        });
    }
  },
  loadPosts() {
    const { page, pageSize, noMore, searchKeyword } = this.data;
    if (this.data.loading || noMore) return;
  
    this.setData({ loading: true });
  
    const db = wx.cloud.database();
    const _ = db.command;
  
    // 构建查询条件
    let queryConditions = { Review: 1 };
    if (searchKeyword) {
      queryConditions = _.and([
        { Review: 1 },
        _.or([
          { title: db.RegExp({ regexp: searchKeyword, options: 'i' }) },
          { account: db.RegExp({ regexp: searchKeyword, options: 'i' }) }
        ])
      ]);
    }
  
    db.collection('travel_notes')
      .where(queryConditions)
      .skip((page - 1) * pageSize)
      .limit(pageSize)
      .get()
      .then(res => {
        const newData = res.data || [];
        if (newData.length === 0) {
          this.setData({ noMore: true });
        } else {
      
          if (page === 1) {
            this.setData({ columns: [[], []] }, () => {
              this.distributeToColumns(newData);
              this.setData({ page: page + 1 });
            });
          } else {
            this.distributeToColumns(newData);
            this.setData({ page: page + 1 });
          }
        }
      })
      .catch(err => {
        wx.showToast({ title: '搜索失败', icon: 'none' });
        console.error('搜索失败:', err);
      })
      .finally(() => {
        this.setData({ loading: false });
      });
  },

  distributeToColumns(data) {
    console.log(this.data.columns)
    const { columns } = this.data;
    const newColumns = [...columns];

    data.forEach((post, index) => {
      newColumns[index % 2].push({
        name: post.account,  
        num: post._id, 
        title: post.title, 
        url: post.image[0],      
        avatar: post.avatar,   
        video: post.video   
      });
    });

    this.setData({ columns: newColumns });
  },

  tomyNotes() {
    wx.navigateTo({
      url: '../myNotes/myNotes',
    });
  },
  toDetail(e){
    wx.navigateTo({
      url: `../noteDetail/noteDetail?id=${e.currentTarget.dataset.id}`,
    })
  },
  onScroll() {
    const query = wx.createSelectorQuery().in(this);
    query.select('scroll-view').boundingClientRect(res => {
      if (res && res.scrollHeight - res.scrollTop - res.height < 20) {
        this.loadPosts();
      }
    }).exec();
  }
});