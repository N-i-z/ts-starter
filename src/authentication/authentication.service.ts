import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import RegisterDto from './dto/register.dto';
import { ConfigService } from '@nestjs/config';
import { JwtUtils } from '../utils/jwt.utils';
import { TokenPayload } from './tokenPayload.interface';

@Injectable()
export class AuthenticationService {
  private jwtUtils: JwtUtils; // Create an instance of JwtUtils

  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
  ) {
    this.jwtUtils = new JwtUtils(configService); // Initialize JwtUtils
  }

  public async getAuthenticatedUser(email: string, plainTextPassword: string) {
    try {
      const user = await this.usersService.getByEmail(email);

      if (!user || !user.password) {
        throw new HttpException(
          'Invalid email or password',
          HttpStatus.BAD_REQUEST,
        );
      }

      await this.verifyPassword(plainTextPassword, user.password);

      // Avoid exposing the password
      user.password = undefined;
      return user;
    } catch (error) {
      throw new HttpException(
        'Wrong credentials provided',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  public async register(registerDto: RegisterDto) {
    const hashedPassword = await bcrypt.hash(registerDto.password, 10);
    const user = await this.usersService.create({
      ...registerDto,
      password: hashedPassword,
    });

    user.password = undefined; // Hide password in response
    return user;
  }

  public getJwtToken(userId: number): string {
    const payload: TokenPayload = { userId };
    return this.jwtUtils.generateToken(payload); // Generate JWT token
  }

  public verifyJwtToken(token: string): any {
    return this.jwtUtils.verifyToken(token); // Verify JWT token
  }

  private async verifyPassword(
    plainTextPassword: string,
    hashedPassword: string,
  ) {
    if (!hashedPassword) {
      throw new HttpException(
        'Password not set for this user',
        HttpStatus.BAD_REQUEST,
      );
    }

    const isPasswordMatching = await bcrypt.compare(
      plainTextPassword,
      hashedPassword,
    );

    if (!isPasswordMatching) {
      throw new HttpException(
        'Wrong credentials provided',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  public getCookieWithJwtToken(userId: number): string {
    const payload: TokenPayload = { userId };
    const token = this.jwtUtils.generateToken(payload); // Generate JWT token
    const expirationTime = this.configService.get<number>(
      'JWT_EXPIRATION_TIME',
    );
    return `Authentication=${token}; HttpOnly; Path=/; Max-Age=${expirationTime}`;
  }

  public getCookieForLogOut(): string {
    return `Authentication=; HttpOnly; Path=/; Max-Age=0`;
  }
}
