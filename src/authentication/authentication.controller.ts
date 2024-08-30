import {
  Body,
  Req,
  Res,
  Controller,
  HttpCode,
  Post,
  Get,
  UseGuards,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import RegisterDto from './dto/register.dto';
import RequestWithUser from './requestWithUser.interface';
import { LocalAuthenticationGuard } from './localAuthentication.guard';
import JwtAuthenticationGuard from './jwt-authentication.guard'; // Import JwtAuthenticationGuard
import { Response } from 'express'; // Import Response type

@Controller('authentication')
export class AuthenticationController {
  constructor(private readonly authenticationService: AuthenticationService) {}

  @Post('register')
  async register(@Body() registrationData: RegisterDto) {
    return this.authenticationService.register(registrationData);
  }

  @HttpCode(200)
  @UseGuards(LocalAuthenticationGuard)
  @Post('log-in')
  async logIn(@Req() request: RequestWithUser, @Res() response: Response) {
    const user = request.user;

    // Check if user.id is defined and of type number
    if (!user.id || typeof user.id !== 'number') {
      throw new HttpException(
        'User ID is missing or invalid',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    // Generate the cookie with JWT token
    const cookie = this.authenticationService.getCookieWithJwtToken(user.id);

    // Set the cookie in the response header
    response.setHeader('Set-Cookie', cookie);

    // Remove password from user object before sending it
    user.password = undefined;

    // Send the response
    return response.send(user);
  }

  @UseGuards(JwtAuthenticationGuard)
  @Post('log-out')
  async logOut(@Req() request: RequestWithUser, @Res() response: Response) {
    // Set the cookie to log out
    response.setHeader(
      'Set-Cookie',
      this.authenticationService.getCookieForLogOut(),
    );

    // Send a successful response
    return response.sendStatus(200);
  }

  @UseGuards(JwtAuthenticationGuard)
  @Get()
  authenticate(@Req() request: RequestWithUser) {
    const user = request.user;
    user.password = undefined; // Remove sensitive information
    return user;
  }
}
