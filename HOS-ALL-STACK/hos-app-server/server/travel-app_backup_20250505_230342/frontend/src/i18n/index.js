import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

const resources = {
  zh: {
    translation: {
      dashboard_title: '欢迎使用旅行应用',
      upload_travel_note: '上传游记',
      all_travel_notes: '所有游记',
      my_travel_notes: '我的游记',
      title_placeholder: '游记标题',
      content_placeholder: '游记内容',
      image_placeholder: '图片URL（可选）',
      upload_button: '上传',
      preview: '预览',
      title_length: '标题长度：{{count}}/255',
      content_length: '内容长度：{{count}}',
      search_placeholder: '搜索游记标题...',
      sort_by_date: '按日期排序',
      sort_by_status: '按状态排序',
      all_status: '所有状态',
      pending: '待审核',
      approved: '已通过',
      rejected: '已拒绝',
      status: '状态',
      reason: '拒绝原因',
      uploader: '上传者',
      approve: '通过',
      reject: '拒绝',
      reason_placeholder: '拒绝原因（拒绝时必填）',
      no_travel_notes: '暂无游记',
      previous: '上一页',
      next: '下一页',
      page_info: '第 {{page}} 页 / 共 {{totalPages}} 页',
      invalid_token: '令牌无效，请重新登录',
      fetch_posts_failed: '获取游记失败',
      title_content_required: '标题和内容不能为空',
      title_too_long: '标题长度不能超过255个字符',
      upload_success: '上传成功',
      upload_failed: '上传失败',
      reason_required: '拒绝时必须提供原因',
      confirm_approve: '确定通过此游记？',
      confirm_reject: '确定拒绝此游记？',
      approve_success: '审核通过',
      reject_success: '审核拒绝',
      review_failed: '审核失败'
    }
  },
  en: {
    translation: {
      dashboard_title: 'Welcome to Travel App',
      upload_travel_note: 'Upload Travel Note',
      all_travel_notes: 'All Travel Notes',
      my_travel_notes: 'My Travel Notes',
      title_placeholder: 'Travel Note Title',
      content_placeholder: 'Travel Note Content',
      image_placeholder: 'Image URL (Optional)',
      upload_button: 'Upload',
      preview: 'Preview',
      title_length: 'Title Length: {{count}}/255',
      content_length: 'Content Length: {{count}}',
      search_placeholder: 'Search travel note titles...',
      sort_by_date: 'Sort by Date',
      sort_by_status: 'Sort by Status',
      all_status: 'All Statuses',
      pending: 'Pending',
      approved: 'Approved',
      rejected: 'Rejected',
      status: 'Status',
      reason: 'Rejection Reason',
      uploader: 'Uploader',
      approve: 'Approve',
      reject: 'Reject',
      reason_placeholder: 'Rejection Reason (Required for Rejection)',
      no_travel_notes: 'No Travel Notes',
      previous: 'Previous',
      next: 'Next',
      page_info: 'Page {{page}} of {{totalPages}}',
      invalid_token: 'Invalid token, please log in again',
      fetch_posts_failed: 'Failed to fetch travel notes',
      title_content_required: 'Title and content are required',
      title_too_long: 'Title cannot exceed 255 characters',
      upload_success: 'Uploaded successfully',
      upload_failed: 'Upload failed',
      reason_required: 'Reason is required for rejection',
      confirm_approve: 'Are you sure to approve this travel note?',
      confirm_reject: 'Are you sure to reject this travel note?',
      approve_success: 'Approved successfully',
      reject_success: 'Rejected successfully',
      review_failed: 'Review failed'
    }
  }
};

i18n
  .use(initReactI18next)
  .init({
    resources,
    lng: 'zh',
    interpolation: {
      escapeValue: false
    }
  });

export default i18n;
