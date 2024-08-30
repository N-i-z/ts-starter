import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import RegisterDto from './dto/register.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { TokenPayload } from './tokenPayload.interface'; // Ensure the correct path

@Injectable()
export class AuthenticationService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  public async getAuthenticatedUser(email: string, plainTextPassword: string) {
    try {
      const user = await this.usersService.getByEmail(email);

      // Ensure that the user's password is defined
      if (!user.password) {
        throw new HttpException(
          'Password not set for this user',
          HttpStatus.BAD_REQUEST,
        );
      }

      await this.verifyPassword(plainTextPassword, user.password);

      // Set password to undefined to avoid exposing it
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
    // Hash the user's password
    const hashedPassword = await bcrypt.hash(registerDto.password, 10);

    // Create a new user with hashed password
    const user = await this.usersService.create({
      ...registerDto,
      password: hashedPassword,
    });

    // Return the newly created user without password
    user.password = undefined;
    return user;
  }

  private async verifyPassword(
    plainTextPassword: string,
    hashedPassword: string,
  ) {
    // If hashedPassword is undefined, throw an error
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

  public getCookieWithJwtToken(userId: number) {
    const payload: TokenPayload = { userId };
    const token = this.jwtService.sign(payload);
    return `Authentication=${token}; HttpOnly; Path=/; Max-Age=${this.configService.get<number>('JWT_EXPIRATION_TIME')}`;
  }

  public getCookieForLogOut() {
    return `Authentication=; HttpOnly; Path=/; Max-Age=0`;
  }
}
