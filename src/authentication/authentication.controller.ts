import {
  Body,
  Req,
  Controller,
  HttpCode,
  Post,
  Get,
  UseGuards,
  HttpException,
  HttpStatus,
  SerializeOptions,
} from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import RegisterDto from './dto/register.dto';
import RequestWithUser from './requestWithUser.interface';
import { LocalAuthenticationGuard } from './localAuthentication.guard';
import JwtAuthenticationGuard from './jwt-authentication.guard';

@Controller('authentication')
@SerializeOptions({
  strategy: 'excludeAll',
})
export class AuthenticationController {
  constructor(private readonly authenticationService: AuthenticationService) {}

  @Post('register')
  async register(@Body() registrationData: RegisterDto) {
    return this.authenticationService.register(registrationData);
  }

  @HttpCode(200)
  @UseGuards(LocalAuthenticationGuard)
  @Post('log-in')
  async logIn(@Req() request: RequestWithUser) {
    const { user } = request;

    // Check if user.id is defined and of type number
    if (!user.id || typeof user.id !== 'number') {
      throw new HttpException(
        'User ID is missing or invalid',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    // Ensure that request.res is defined
    if (request.res) {
      // Generate the cookie with JWT token
      const cookie = this.authenticationService.getCookieWithJwtToken(user.id);

      // Set the cookie in the response header using request.res
      request.res.setHeader('Set-Cookie', cookie);
    } else {
      throw new HttpException(
        'Response object is missing',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    // Remove password from user object before sending it
    user.password = undefined;

    // Return the user object directly
    return user;
  }

  @UseGuards(JwtAuthenticationGuard)
  @Post('log-out')
  async logOut(@Req() request: RequestWithUser) {
    // Ensure that request.res is defined
    if (request.res) {
      // Set the cookie to log out using request.res
      request.res.setHeader(
        'Set-Cookie',
        this.authenticationService.getCookieForLogOut(),
      );

      // Send a successful response
      return { message: 'Logged out successfully' };
    } else {
      throw new HttpException(
        'Response object is missing',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @UseGuards(JwtAuthenticationGuard)
  @Get()
  authenticate(@Req() request: RequestWithUser) {
    const user = request.user;
    user.password = undefined; // Remove sensitive information
    return user;
  }
}
