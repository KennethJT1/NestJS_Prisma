import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import { hash, compare } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JWT_SECRET } from '../utils/constants';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  async signup(dto: AuthDto) {
    const { email, password } = dto;

    const existUser = await this.prisma.user.findUnique({ where: { email } });

    if (existUser) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await this.hashPassowrd(password);

    const newUser = await this.prisma.user.create({
      data: {
        email,
        hashedPassword,
      },
    });

    return {
      msg: 'user created successfully',
      newUser,
    };
  }

  async signin(dto: AuthDto, req: Request, res: Response) {
    const { email, password } = dto;

    const existUser = await this.prisma.user.findUnique({ where: { email } });

    if (!existUser) {
      throw new BadRequestException('Wrong Credentials');
    }

    const isPassword = await this.comparePassword(
      password,
      existUser.hashedPassword,
    );

    if (!isPassword) {
      throw new BadRequestException('Wrong Credentials');
    }

    const token = await this.signToken(existUser.id, existUser.email);

    if (!token) {
      throw new ForbiddenException();
    }

    res.cookie('token', token);

    return res.send('Login successfully');
  }

  async signout() {
    return {};
  }

  async hashPassowrd(password: string) {
    return await hash(password, 10);
  }

  async comparePassword(password: string, dbPassword: string) {
    return await compare(password, dbPassword);
  }

  async signToken(id: string, email: string) {
    return this.jwt.signAsync({ id, email }, { secret: JWT_SECRET });
  }
}
