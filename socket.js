import { Server } from "socket.io";
let io;

const socket = {
  init: (httpServer) => {
    io = new Server(httpServer, {
      cors: {
        methods: ["GET", "POST"],
      },
    });
    return io;
  },
  getIO: () => {
    if (!io) {
      throw new Error("Socket.io not initialized!")
    }
    return io
  }
};

export default  socket