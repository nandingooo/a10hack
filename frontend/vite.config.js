export default ({ mode }) => {
  const target = process.env.TRUSTAGENT_BACKEND || (mode === 'demo' ? 'http://127.0.0.1:8787' : 'http://127.0.0.1:8798');
  const proxy = { '/auth': { target, changeOrigin: true }, '/api': { target, changeOrigin: true } };
  return { server: { host: '127.0.0.1', proxy } };
};
