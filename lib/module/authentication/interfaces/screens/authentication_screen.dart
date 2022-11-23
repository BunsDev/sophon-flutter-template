import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:sophon/configs/themes.dart';
import 'package:sophon/module/authentication/service/cubit/auth_cubit.dart';
import 'package:sophon/module/home/interfaces/screens/home_screen.dart';
import 'package:url_launcher/url_launcher_string.dart';

class AuthenticationScreen extends StatefulWidget {
  const AuthenticationScreen({Key? key}) : super(key: key);

  @override
  State<AuthenticationScreen> createState() => _AuthenticationScreenState();
}

class _AuthenticationScreenState extends State<AuthenticationScreen> {
  @override
  void initState() {
    super.initState();
    context.read<AuthCubit>().initiateListeners();
  }

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    final double width = MediaQuery.of(context).size.width;
    final double height = MediaQuery.of(context).size.height;

    return BlocListener<AuthCubit, AuthState>(
      listener: (context, state) {
        if (state is EstablishConnectionSuccess) {
          Navigator.of(context).push(
            MaterialPageRoute(
              builder: (context) => HomeScreen(
                session: state.session,
                connector: state.connector,
                uri: state.uri,
              ),
            ),
          );
        } else if (state is LoginWithMetamaskSuccess) {
          launchUrlString(state.url, mode: LaunchMode.externalApplication);
        } else if (state is LoginWithMetamaskFailed) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(state.message),
              backgroundColor: theme.errorColor,
            ),
          );
        }
      },
      child: Scaffold(
        body: DecoratedBox(
          decoration: const BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.bottomCenter,
              end: Alignment.topCenter,
              colors: violetGradient,
            ),
          ),
          child: Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Image.asset(
                  'assets/images/logo.png',
                  width: width * 0.7,
                ),
                Container(
                  padding: EdgeInsets.symmetric(
                    horizontal: width * 0.08,
                    vertical: height * 0.05,
                  ),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(10),
                    color: Colors.white24,
                    border: Border.all(color: kLightViolet),
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        'Connect your Ethereum Wallet to',
                        textAlign: TextAlign.center,
                        style: theme.textTheme.titleMedium?.copyWith(
                          fontWeight: FontWeight.w300,
                        ),
                      ),
                      Text(
                        'Sophon',
                        style: theme.textTheme.titleLarge?.copyWith(
                          fontWeight: FontWeight.w300,
                        ),
                      ),
                      Padding(
                        padding: const EdgeInsets.only(top: 8.0),
                        child: ElevatedButton.icon(
                          onPressed: () =>
                              context.read<AuthCubit>().loginWithMetamask(),
                          icon: Image.asset(
                            'assets/images/metamask-logo.png',
                            width: 16,
                          ),
                          label: const Text('Connect to MetaMask'),
                          style: ButtonStyle(
                            backgroundColor: MaterialStateProperty.all(kViolet),
                            elevation: MaterialStateProperty.all(0),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
