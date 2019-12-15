FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-buster-slim AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
WORKDIR /src
COPY ["NETCoreAuthAPI/NETCoreAuthAPI.csproj", "NETCoreAuthAPI/"]
RUN dotnet restore "NETCoreAuthAPI/NETCoreAuthAPI.csproj"
COPY . .
WORKDIR "/src/NETCoreAuthAPI"
RUN dotnet build "NETCoreAuthAPI.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "NETCoreAuthAPI.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "NETCoreAuthAPI.dll"]