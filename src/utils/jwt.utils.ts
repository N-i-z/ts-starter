import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';

export class JwtUtils {
  private readonly secret: string;

  constructor(configService: ConfigService) {
    this.secret = configService.get<string>('JWT_SECRET')!;
  }

  public generateToken(payload: object): string {
    return jwt.sign(payload, this.secret, { expiresIn: '1h' });
  }

  public verifyToken(token: string): any {
    try {
      return jwt.verify(token, this.secret);
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  }
}
