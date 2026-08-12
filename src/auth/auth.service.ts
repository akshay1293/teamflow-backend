import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { randomUUID } from 'crypto';
import * as argon2 from 'argon2';
import { Prisma } from 'generated/prisma/client';
import { RegisterResponseDto } from './dto/register-response.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}
  async register(registerDto: RegisterDto): Promise<RegisterResponseDto> {
    const email = registerDto.email.trim().toLowerCase();

    const existingUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });
    if (existingUser) {
      throw new ConflictException('Email is already registered');
    }
    const passwordHash = await argon2.hash(registerDto.password);
    try {
      const user = await this.prisma.user.create({
        data: {
          id: randomUUID(),
          email,
          passwordHash,
        },
      });
      return {
        id: user.id,
        email: user.email,
        emailVerifiedAt: user.emailVerifiedAt,
        createdAt: user.createdAt,
      };
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException('Email is already registered');
      }
      throw error;
    }
  }

  async login(loginDto: LoginDto) {
    const email = loginDto.email.trim().toLowerCase();

    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }
    const passwordMatches = await argon2.verify(
      user.passwordHash,
      loginDto.password,
    );

    if (!passwordMatches) {
      throw new UnauthorizedException('Invalid email or password');
    }
    if (!user.emailVerifiedAt) {
      throw new UnauthorizedException('Email is not verified');
    }

    return {
      message: 'Login successful',
    };
  }
}
