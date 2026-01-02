import react from '@vitejs/plugin-react-swc';
import path from 'path';
import { defineConfig } from 'vite';
import svgr from 'vite-plugin-svgr';
import tsconfigPaths from 'vite-tsconfig-paths';

// https://vitejs.dev/config/
export default defineConfig({
  build: {
    sourcemap: false
  },
  plugins: [react(), tsconfigPaths(), svgr()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      // To prevent conflicts with packages in @chainlit/react-client, we need to specify the resolution paths for these dependencies.
      react: path.resolve(__dirname, './node_modules/react'),
      'usehooks-ts': path.resolve(__dirname, './node_modules/usehooks-ts'),
      sonner: path.resolve(__dirname, './node_modules/sonner'),
      lodash: path.resolve(__dirname, './node_modules/lodash'),
      recoil: path.resolve(__dirname, './node_modules/recoil')
    }
  },
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,

    // 你是通过本机端口转发访问的，所以浏览器侧就是 localhost:35173
    hmr: {
      host: "localhost",
      clientPort: 35173,
      protocol: "ws",
    },

    proxy: {
      "/auth":    { target: "http://127.0.0.1:8000", changeOrigin: true },
      "/project": { target: "http://127.0.0.1:8000", changeOrigin: true },
      "/api":     { target: "http://127.0.0.1:8000", changeOrigin: true },

      "/set-session-cookie": { target: "http://127.0.0.1:8000", changeOrigin: true },
    
      "/ws":       { target: "ws://127.0.0.1:8000", ws: true },
      "/socket.io":{ target: "ws://127.0.0.1:8000", ws: true },
    }
  },
});
