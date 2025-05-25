import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { FaSearch, FaSort, FaFilter, FaCheck, FaTimes } from 'react-icons/fa';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import debounce from 'lodash.debounce';
import { useTranslation } from 'react-i18next';
import './i18n';

const Dashboard = () => {
  const { t, i18n } = useTranslation();
  const [role, setRole] = useState('');
  const [posts, setPosts] = useState([]);
  const [formData, setFormData] = useState({ title: '', content: '', image: '' });
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [limit] = useState(10);
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState('created_at');
  const [order, setOrder] = useState('DESC');
  const [statusFilter, setStatusFilter] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [preview, setPreview] = useState('');

  // 初始化zor initialization
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      window.location.href = '/login';
      return;
    }

    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      setRole(payload.role);
      fetchPosts(token, page, search, sort, order, statusFilter);
    } catch (err) {
      setError(t('invalid_token'));
      window.location.href = '/login';
    }
  }, [page, search, sort, order, statusFilter, t]);

  // 获取游记
  const fetchPosts = async (token, page, search, sort, order, status) => {
    setIsLoading(true);
    try {
      const response = await axios.get(`/api/posts?page=${page}&limit=${limit}&search=${search}&sort=${sort}&order=${order}&status=${status}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setPosts(response.data.posts);
      setTotalPages(response.data.totalPages);
      setIsLoading(false);
    } catch (err) {
      toast.error(err.response?.data?.message || t('fetch_posts_failed'));
      setIsLoading(false);
    }
  };

  // 上传游记
  const handleSubmit = async (e) => {
    e.preventDefault();
    const { title, content } = formData;

    if (!title.trim() || !content.trim()) {
      toast.error(t('title_content_required'));
      return;
    }
    if (title.length > 255) {
      toast.error(t('title_too_long'));
      return;
    }

    const token = localStorage.getItem('token');
    setIsLoading(true);
    try {
      await axios.post('/api/posts', formData, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setFormData({ title: '', content: '', image: '' });
      setPreview('');
      toast.success(t('upload_success'));
      fetchPosts(token, page, search, sort, order, statusFilter);
    } catch (err) {
      toast.error(err.response?.data?.message || t('upload_failed'));
    } finally {
      setIsLoading(false);
    }
  };

  // 审核游记
  const handleReview = async (id, status) => {
    if (status === 'rejected' && !reason.trim()) {
      toast.error(t('reason_required'));
      return;
    }

    if (!window.confirm(t(status === 'approved' ? 'confirm_approve' : 'confirm_reject'))) {
      return;
    }

    const token = localStorage.getItem('token');
    setIsLoading(true);
    try {
      await axios.put(`/api/posts/${id}`, { status, reason }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setReason('');
      toast.success(t(status === 'approved' ? 'approve_success' : 'reject_success'));
      fetchPosts(token, page, search, sort, order, statusFilter);
    } catch (err) {
      toast.error(err.response?.data?.message || t('review_failed'));
    } finally {
      setIsLoading(false);
    }
  };

  // 输入处理
  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
    if (name === 'content') {
      setPreview(value);
    }
  };

  // 防抖搜索
  const debouncedSearch = useCallback(
    debounce((value) => {
      setSearch(value);
      setPage(1);
    }, 500),
    []
  );

  // 切换语言
  const toggleLanguage = () => {
    const newLang = i18n.language === 'zh' ? 'en' : 'zh';
    i18n.changeLanguage(newLang);
  };

  return (
    <div className="min-h-screen bg-gray-100 p-4">
      <ToastContainer />
      <div className="max-w-4xl mx-auto bg-white rounded-lg shadow-lg p-6">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold text-gray-800">{t('dashboard_title')}</h2>
          <button
            onClick={toggleLanguage}
            className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
          >
            {i18n.language === 'zh' ? 'English' : '中文'}
          </button>
        </div>

        {error && <p className="text-red-500 mb-4">{error}</p>}

        {role === 'user' && (
          <div className="mb-8">
            <h3 className="text-xl font-semibold mb-4">{t('upload_travel_note')}</h3>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <input
                  type="text"
                  name="title"
                  placeholder={t('title_placeholder')}
                  value={formData.title}
                  onChange={handleChange}
                  className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
                <p className="text-sm text-gray-500 mt-1">
                  {t('title_length', { count: formData.title.length })}
                </p>
              </div>
              <div>
                <textarea
                  name="content"
                  placeholder={t('content_placeholder')}
                  value={formData.content}
                  onChange={handleChange}
                  className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500 h-32"
                  required
                />
                <p className="text-sm text-gray-500 mt-1">
                  {t('content_length', { count: formData.content.length })}
                </p>
              </div>
              <div>
                <input
                  type="text"
                  name="image"
                  placeholder={t('image_placeholder')}
                  value={formData.image}
                  onChange={handleChange}
                  className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <button
                type="submit"
                className="w-full py-2 bg-blue-500 text-white rounded hover:bg-blue-600 flex items-center justify-center"
                disabled={isLoading}
              >
                {isLoading ? (
                  <svg className="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                  </svg>
                ) : null}
                {t('upload_button')}
              </button>
            </form>
            {preview && (
              <div className="mt-4 p-4 border rounded bg-gray-50">
                <h4 className="text-lg font-semibold">{t('preview')}</h4>
                <p>{preview}</p>
              </div>
            )}
          </div>
        )}

        <div>
          <h3 className="text-xl font-semibold mb-4">
            {role === 'admin' ? t('all_travel_notes') : t('my_travel_notes')}
          </h3>
          {role === 'admin' && (
            <div className="flex flex-col md:flex-row gap-4 mb-4">
              <div className="flex-1 relative">
                <FaSearch className="absolute left-3 top-3 text-gray-500" />
                <input
                  type="text"
                  placeholder={t('search_placeholder')}
                  onChange={(e) => debouncedSearch(e.target.value)}
                  className="w-full pl-10 p-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <select
                onChange={(e) => {
                  setSort(e.target.value);
                  setPage(1);
                }}
                className="p-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="created_at">{t('sort_by_date')}</option>
                <option value="status">{t('sort_by_status')}</option>
              </select>
              <select
                onChange={(e) => {
                  setStatusFilter(e.target.value);
                  setPage(1);
                }}
                className="p-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">{t('all_status')}</option>
                <option value="pending">{t('pending')}</option>
                <option value="approved">{t('approved')}</option>
                <option value="rejected">{t('rejected')}</option>
              </select>
            </div>
          )}

          {isLoading ? (
            <div className="flex justify-center">
              <svg className="animate-spin h-8 w-8 text-blue-500" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
              </svg>
            </div>
          ) : posts.length === 0 ? (
            <p className="text-gray-500">{t('no_travel_notes')}</p>
          ) : (
            <>
              <ul className="space-y-4">
                {posts.map(post => (
                  <li key={post.id} className="p-4 border rounded bg-white shadow-sm">
                    <h4 className="text-lg font-semibold text-blue-600">{post.title}</h4>
                    <p className="text-gray-700">{post.content}</p>
                    {post.image && (
                      <img src={post.image} alt={post.title} className="mt-2 max-w-full h-auto rounded" />
                    )}
                    <p className="text-sm text-gray-500">
                      {t('status')}: {t(post.status)}
                    </p>
                    {post.reason && (
                      <p className="text-sm text-red-500">{t('reason')}: {post.reason}</p>
                    )}
                    {role === 'admin' && (
                      <div className="mt-2">
                        <p className="text-sm text-gray-500">
                          {t('uploader')}: {post.User?.username} ({post.User?.phone_number})
                        </p>
                        {post.status === 'pending' && (
                          <div className="mt-2 space-y-2">
                            <textarea
                              placeholder={t('reason_placeholder')}
                              value={reason}
                              onChange={(e) => setReason(e.target.value)}
                              className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                            <div className="flex space-x-2">
                              <button
                                onClick={() => handleReview(post.id, 'approved')}
                                className="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600 flex items-center"
                              >
                                <FaCheck className="mr-2" /> {t('approve')}
                              </button>
                              <button
                                onClick={() => handleReview(post.id, 'rejected')}
                                className="px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600 flex items-center"
                              >
                                <FaTimes className="mr-2" /> {t('reject')}
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
              {totalPages > 1 && (
                <div className="flex justify-center items-center space-x-4 mt-6">
                  <button
                    onClick={() => setPage(page - 1)}
                    disabled={page === 1}
                    className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:bg-gray-300"
                  >
                    {t('previous')}
                  </button>
                  <span className="text-gray-700">
                    {t('page_info', { page, totalPages })}
                  </span>
                  <button
                    onClick={() => setPage(page + 1)}
                    disabled={page === totalPages}
                    className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:bg-gray-300"
                  >
                    {t('next')}
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
