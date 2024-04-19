import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from '../auth.service';

// Guard는 Reqeust 컨텍스트에 접근할 수 있다.
@Injectable()
export class BasicTokenGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // request에 접근 후 토큰 헤더를 확인하여 헤더가 없다면 에러 쓰로우
    const req = context.switchToHttp().getRequest();
    const rawToken = req.headers['authorization'];
    if (!rawToken) throw new UnauthorizedException('no token');

    // 헤더로부터 토큰을 추출한 후 Base64로 암호화된 basic 토큰을 해석
    // 토큰으로부터 추출한 email과 password를 바탕으로 로그인 진행
    const token = this.authService.extractTokenFromHeader(rawToken, false);
    const { email, password } = this.authService.decodedBasicToken(token);
    const user = await this.authService.authenticateWithEmailAndPassword({
      email,
      password,
    });

    // 로그인이 성공했다면 request의 user 프로퍼티에 user 객체를 집어넣고 가드 통과
    req.user = user;
    return true;
  }
}
