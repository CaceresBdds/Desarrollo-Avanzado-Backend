import express from 'express';
import handlebars from 'express-handlebars';
import { Server } from 'socket.io';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import 'dotenv/config';

import productRouter from './routes/productRouter.js';
import cartRouter from './routes/cartRouter.js';
import viewsRouter from './routes/viewsRouter.js';
import sessionsRouter from './routes/sessionsRouter.js';
import usersRouter from './routes/usersRouter.js';
import __dirname from './utils/constantsUtil.js';
import websocket from './websocket.js';
import { initializePassport } from './config/passport.config.js';

const app = express();

mongoose.connect(process.env.MONGO_URL);

app.engine('handlebars', handlebars.engine());
app.set('views', __dirname + '/../views');
app.set('view engine', 'handlebars');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
initializePassport();
app.use(passport.initialize());
app.use(express.static('public'));

app.use('/api/products', productRouter);
app.use('/api/carts', cartRouter);
app.use('/api/sessions', sessionsRouter);
app.use('/api/users', usersRouter);
app.use('/', viewsRouter);

const PORT = process.env.PORT || 8080;
const httpServer = app.listen(PORT, () => {
  console.log(`Start server in PORT ${PORT}`);
});

const io = new Server(httpServer);
websocket(io);
