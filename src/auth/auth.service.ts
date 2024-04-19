import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from 'src/users/dto';
import { User } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UsersService,
  ) {}

  /**
   * 이메일 기반의 ID를 DB에 등록시켜 회원가입한다.
   * 가입이 이루어지면 자동으로 로그인을 시도한다.
   * @param user
   * @returns {newUser} username, accessToken, refreshToken
   */
  async registerWithEmail(user: CreateUserDto) {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    const newUser = await this.userService.create({
      ...user,
      password: hashedPassword,
    });
    return this.loginUser(newUser);
  }

  /**
   * 로그인 성공시 유저에게 전달할 객체를 만든다.
   * 객체에는 username, accessToken, refreshToken이 키값으로 주어진다.
   * @param user
   * @returns {userData} username, accessToken, refreshToken
   */
  loginUser(user: Pick<User, 'id' | 'email' | 'name'>) {
    return {
      username: user.name,
      accessToken: this.signToken({ id: user.id, email: user.email }, false),
      refreshToken: this.signToken({ id: user.id, email: user.email }, true),
    };
  }

  /**
   * 토큰을 만든다.
   * 리프레시 토큰은 3600초, 엑세스 토큰은 600초의 만료시간이 주어진다.
   * @param user
   * @param isRefreshToken
   * @returns {payload} email, sub, type
   */
  signToken(user: Pick<User, 'id' | 'email'>, isRefreshToken: boolean) {
    const payload = {
      email: user.email,
      sub: user.id,
      type: isRefreshToken ? 'refresh' : 'access',
    };

    return this.jwtService.sign(payload, {
      secret: 'test-jwt-key',
      expiresIn: isRefreshToken ? 3600 : 600,
    });
  }

  /**
   * 이메일 로그인을 시도한다.
   * 전달받은 email, password로 DB 내 저장된 계정을 대조하여 로그인한다.
   * @param user
   * @returns {userData} username, accessToken, refreshToken
   */
  async loginWithEmail(user: Pick<User, 'email' | 'password'>) {
    const existingUser = await this.authenticateWithEmailAndPassword(user);
    return this.loginUser(existingUser);
  }

  /**
   * headers.authorization의 토큰을 추출한다.
   * @param header
   * @param isBearer
   * @returns string
   */
  extractTokenFromHeader(header: string, isBearer: boolean) {
    const splitToken = header.split(' ');
    const prefix = isBearer ? 'Bearer' : 'Basic';
    if (splitToken.length !== 2 || splitToken[0] !== prefix)
      throw new UnauthorizedException('wrong token');

    const token = splitToken[1];
    return token;
  }

  /**
   * BasicToken의 <id>:<email> 형태의 base64 버퍼를 해독하여 리턴한다.
   * @param base64String
   * @returns email, password
   */
  decodedBasicToken(base64String: string) {
    const decoded = Buffer.from(base64String, 'base64').toString('utf-8');
    console.log(decoded);
    const split = decoded.split(':');
    if (split.length !== 2) throw new UnauthorizedException('wrong token');
    const [email, password] = split;
    return {
      email,
      password,
    };
  }

  /**
   * 아이디와 패스워드를 인증한다.
   * 인증이 완료되면 DB에 저장된 유저의 정보를 그대로 반환한다.
   * @param user
   * @returns id, email, name, password
   */
  async authenticateWithEmailAndPassword(
    user: Pick<User, 'email' | 'password'>,
  ) {
    // 아이디가 존재하는지 확인
    const existingUser = await this.userService.getUserByEmail(user.email);
    if (!existingUser) throw new UnauthorizedException('not exist user');

    // 비밀번호가 맞는지 확인
    const passOk = await bcrypt.compare(user.password, existingUser.password);
    if (!passOk) throw new UnauthorizedException('the password does not match');

    return existingUser;
  }
}
