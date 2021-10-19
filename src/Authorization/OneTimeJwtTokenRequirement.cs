using Microsoft.AspNetCore.Authorization;

namespace Authorization.Samples.Authorization
{
    public class OneTimeJwtTokenRequirement : IAuthorizationRequirement
    {
        public OneTimeJwtTokenRequirement(string redisKeyPrefix)
        {
            RedisKeyPrefix = redisKeyPrefix;
        }

        public string RedisKeyPrefix { get; }
    }
}