import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { REQUEST_USER_KEY } from '../iam.constants';

export const ActiveUser = createParamDecorator(
  (field: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    console.log('1')
    const user = request[REQUEST_USER_KEY];
    console.log('2')
    console.log(user)
    return field ? user?.[field] : user;
  },
);
