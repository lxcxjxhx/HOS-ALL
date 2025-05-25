const zlib = require('zlib');

const text = '测试文本';
zlib.deflate(text, (err, buffer) => {
  if (err) {
    console.error('压缩失败:', err);
    return;
  }
  console.log('压缩成功:', buffer);
  zlib.inflate(buffer, (err, decompressed) => {
    if (err) {
      console.error('解压缩失败:', err);
      return;
    }
    console.log('解压缩成功:', decompressed.toString());
  });
});
